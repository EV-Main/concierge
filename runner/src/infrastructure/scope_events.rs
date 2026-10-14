//! Postgres adapter for the relying-party streams (`scope_members`, `scope_outbox`,
//! migration 0033).
//!
//! The WRITES are free functions on an open transaction, called by the adapters whose
//! transactions change what an event describes — a grant or revocation
//! ([`super::grants`]), a catalog publication (same), a relying-party sign-in
//! ([`super::relying_parties`]), a role change ([`super::users::drain_outbox`]) — so the
//! event commits with the change or not at all. SCOPE_CHANGED alone is written by the
//! database (a trigger on `tenants`), because the registry has no writer in this binary.
//!
//! Every write takes its locks in ONE order, the order every caller already holds them
//! in: `users` rows, then `tenants` rows (`FOR SHARE`, so a catalog publication — which
//! holds its tenant `FOR UPDATE` — is waited for and its catalog read once committed),
//! then `scope_members` rows by `(scope, user_id)`, then the stream's advisory lock inside
//! `scope_outbox_append`. A per-(scope, user) row lock is what serialises two changes to
//! one person's set, so the second computes from what the first committed.
//!
//! [`reconcile`] runs at boot: it backfills the members and grants that existed before
//! this table did, and repairs what an older binary changed beside this one during a
//! rollout without writing the stream.

use async_trait::async_trait;
use domain::{
	authz::Role,
	error::DomainError,
	iam::{self, Catalog, Target},
	users::UserId,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::grants::{PgGrants, current_catalog};
use crate::ports::{GrantRepository, MemberSnapshot, ScopeClientRecord, ScopeEventBody, ScopeEventRecord, ScopeEventRepository, ScopeRecord};

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

fn unix_now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// How a user became visible to a scope (`scope_members.joined_by`).
#[derive(Clone, Copy, Debug)]
pub enum JoinedBy {
	SignIn,
	Grant,
}

impl JoinedBy {
	fn as_str(self) -> &'static str {
		match self {
			Self::SignIn => "sign_in",
			Self::Grant => "grant",
		}
	}
}

#[derive(Deserialize, Serialize)]
struct MemberJson {
	email: String,
	email_verified: bool,
	username: String,
	preferred_name: String,
	status: String,
	kyc_level: u32,
	token_version: u64,
	lifecycle_sequence: u64,
}

#[derive(Deserialize, Serialize)]
struct GrantsJson {
	permissions: Vec<String>,
}

/// `scope_snapshot()`'s shape (migration 0033).
#[derive(Deserialize)]
struct ScopeJson {
	id: String,
	namespace: String,
	parent: String,
	display_name: String,
	origins: Vec<String>,
	return_paths: Vec<String>,
	observers: Vec<String>,
	state: String,
	version: u64,
	created_at: i64,
	clients: Vec<ClientJson>,
}

#[derive(Deserialize)]
struct ClientJson {
	client_id: String,
	audience: String,
	disabled: bool,
}

async fn append(conn: &mut PgConnection, scope: &str, kind: &str, sequence: i64, user: (UserId, &str), payload: serde_json::Value) -> Result<(), DomainError> {
	sqlx::query("SELECT scope_outbox_append($1, $2, $3, $4, $5, $6, $7)")
		.bind(scope)
		.bind(kind)
		.bind(unix_now())
		.bind(sequence)
		.bind(user.0.raw())
		.bind(user.1)
		.bind(payload)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

/// Make `user` visible to `scope` if they are not yet, then bring their grants there up
/// to date. Joining writes MEMBER_JOINED with the identity snapshot, taken from the
/// `users` row held `FOR SHARE` so no lifecycle event can commit between the snapshot and
/// the membership: every row a relying party is later served for this user is one the
/// snapshot does not already reflect.
pub(crate) async fn join(conn: &mut PgConnection, scope: &str, user: UserId, by: JoinedBy) -> Result<(), DomainError> {
	#[derive(sqlx::FromRow)]
	struct Row {
		auth_subject: String,
		email: Option<String>,
		email_verified: bool,
		username: Option<String>,
		preferred_name: Option<String>,
		status: String,
		kyc_level: i32,
		token_version: i64,
		row_version: i64,
	}
	let row: Row = sqlx::query_as("SELECT auth_subject, email, email_verified, username, preferred_name, status, kyc_level, token_version, row_version FROM users WHERE id = $1 FOR SHARE")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "user",
			id: user.to_string(),
		})?;
	lock_tenant(conn, scope).await?;
	let joined = sqlx::query(
		"INSERT INTO scope_members (scope, user_id, joined_at, joined_by, lifecycle_sequence, sequence, permissions) VALUES ($1, $2, $3, $4, $5, 1, '{}') \
		 ON CONFLICT (scope, user_id) DO NOTHING",
	)
	.bind(scope)
	.bind(user.raw())
	.bind(unix_now())
	.bind(by.as_str())
	.bind(row.row_version)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?
	.rows_affected()
		== 1;
	if joined {
		let member = MemberJson {
			email: row.email.unwrap_or_default(),
			email_verified: row.email_verified,
			username: row.username.unwrap_or_default(),
			preferred_name: row.preferred_name.unwrap_or_default(),
			status: row.status,
			kyc_level: u32::try_from(row.kyc_level).map_err(|_| DomainError::Repository(format!("user {user} has a negative kyc_level")))?,
			token_version: row.token_version as u64,
			lifecycle_sequence: row.row_version as u64,
		};
		let payload = serde_json::to_value(member).map_err(|e| DomainError::Repository(format!("member snapshot does not encode: {e}")))?;
		append(conn, scope, "MEMBER_JOINED", 1, (user, &row.auth_subject), payload).await?;
		tracing::info!(%scope, user_id = %user, joined_by = by.as_str(), "scope member joined");
	}
	sync_member(conn, scope, user).await
}

async fn lock_tenant(conn: &mut PgConnection, scope: &str) -> Result<(String, bool), DomainError> {
	sqlx::query_as("SELECT namespace, granting_seats_hold_all FROM tenants WHERE id = $1 FOR SHARE")
		.bind(scope)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "scope",
			id: scope.to_owned(),
		})
}

/// What `role` and `targets` hold in a tenant: the concrete set `GetMe` answers that
/// tenant's relying party, by the persisted seat (emergency access is decided per request
/// and is nobody's standing state).
fn concrete(role: Role, hold_all: bool, targets: &[Target], catalog: Option<&Catalog>) -> Vec<String> {
	catalog.map_or_else(Vec::new, |catalog| iam::resolve(role, hold_all, targets, catalog).into_iter().map(str::to_owned).collect())
}

/// Re-state `user`'s concrete set in `scope` if it moved since the last event: one
/// GRANTS_CHANGED with the whole set, under the next per-(scope, user) sequence. Nothing
/// when they are not a member — visibility comes from [`join`], never from here.
pub(crate) async fn sync_member(conn: &mut PgConnection, scope: &str, user: UserId) -> Result<(), DomainError> {
	let (namespace, hold_all) = lock_tenant(conn, scope).await?;
	let member: Option<(i64, Vec<String>)> = sqlx::query_as("SELECT sequence, permissions FROM scope_members WHERE scope = $1 AND user_id = $2 FOR UPDATE")
		.bind(scope)
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	let Some((sequence, stated)) = member else {
		return Ok(());
	};
	let (role, auth_subject): (String, String) = sqlx::query_as("SELECT role, auth_subject FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)?;
	let targets: Vec<String> = sqlx::query_scalar("SELECT target FROM grants WHERE user_id = $1 AND namespace = $2 AND revoked_at IS NULL ORDER BY target")
		.bind(user.raw())
		.bind(&namespace)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	let targets = targets.iter().map(|t| Target::parse(t)).collect::<Result<Vec<_>, _>>()?;
	let tenant = current_catalog(conn, &namespace).await?;
	let held = concrete(Role::parse(&role)?, hold_all, &targets, tenant.as_ref().map(|t| &t.catalog));
	if held == stated {
		return Ok(());
	}
	let next = sequence + 1;
	sqlx::query("UPDATE scope_members SET sequence = $3, permissions = $4 WHERE scope = $1 AND user_id = $2")
		.bind(scope)
		.bind(user.raw())
		.bind(next)
		.bind(&held)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	let payload = serde_json::to_value(GrantsJson { permissions: held }).map_err(|e| DomainError::Repository(format!("grant set does not encode: {e}")))?;
	append(conn, scope, "GRANTS_CHANGED", next, (user, &auth_subject), payload).await
}

/// A grant or revocation in `namespace`: holding a grant there makes the user visible to
/// its scope, and the set is re-stated either way.
pub(crate) async fn grants_moved(conn: &mut PgConnection, namespace: &str, user: UserId) -> Result<(), DomainError> {
	let scope: Option<String> = sqlx::query_scalar("SELECT id FROM tenants WHERE namespace = $1")
		.bind(namespace)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	match scope {
		Some(scope) => join(conn, &scope, user, JoinedBy::Grant).await,
		None => Ok(()),
	}
}

/// A catalog publication moved what every holder's aliases and patterns mean: re-state
/// each member's set. Called holding the tenant `FOR UPDATE`; the member rows are locked
/// in one ordered statement before anything is appended.
pub(crate) async fn catalog_moved(conn: &mut PgConnection, scope: &str) -> Result<(), DomainError> {
	let members: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM scope_members WHERE scope = $1 ORDER BY user_id FOR UPDATE")
		.bind(scope)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	for user in members {
		sync_member(conn, scope, UserId::from_raw(user)).await?;
	}
	Ok(())
}

/// A seat change moves what the user holds in every tenant whose granting seats hold all.
pub(crate) async fn seat_moved(conn: &mut PgConnection, user: UserId) -> Result<(), DomainError> {
	let scopes: Vec<String> = sqlx::query_scalar("SELECT scope FROM scope_members WHERE user_id = $1 ORDER BY scope")
		.bind(user.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	for scope in scopes {
		sync_member(conn, &scope, user).await?;
	}
	Ok(())
}

/// A relying party opened a session for `user`: they signed in through one of the
/// client's scope's clients.
pub(crate) async fn signed_in(conn: &mut PgConnection, client_id: &str, user: UserId) -> Result<(), DomainError> {
	let scope: String = sqlx::query_scalar("SELECT tenant_id FROM rp_clients WHERE client_id = $1")
		.bind(client_id)
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)?;
	join(conn, &scope, user, JoinedBy::SignIn).await
}

/// Bring the stream up to what the tables say: every (scope, user) that ever held a grant
/// or opened a client session is a member, and every member's last stated set is the set
/// they hold now. Decided in memory from a few bulk reads, then each disagreement is
/// re-decided under its locks in a transaction of its own, so this never holds the
/// stream's lock while waiting on a user's row.
pub async fn reconcile(pool: &PgPool) -> Result<(), DomainError> {
	let absent: Vec<(String, Uuid, String)> = sqlx::query_as(
		"SELECT DISTINCT ON (scope, user_id) scope, user_id, joined_by FROM ( \
			SELECT t.id AS scope, g.user_id, 'grant' AS joined_by, 0 AS rank FROM grants g JOIN tenants t ON t.namespace = g.namespace \
			UNION ALL \
			SELECT c.tenant_id, s.user_id, 'sign_in', 1 FROM rp_sessions s JOIN rp_clients c ON c.client_id = s.client_id \
		 ) seen \
		 WHERE NOT EXISTS (SELECT 1 FROM scope_members m WHERE m.scope = seen.scope AND m.user_id = seen.user_id) \
		 ORDER BY scope, user_id, rank",
	)
	.fetch_all(pool)
	.await
	.map_err(repo_err)?;
	for (scope, user, by) in &absent {
		let by = if by == "grant" { JoinedBy::Grant } else { JoinedBy::SignIn };
		let mut tx = pool.begin().await.map_err(repo_err)?;
		join(&mut tx, scope, UserId::from_raw(*user), by).await?;
		tx.commit().await.map_err(repo_err)?;
	}

	let stale = stale_members(pool).await?;
	for (scope, user) in &stale {
		let mut tx = pool.begin().await.map_err(repo_err)?;
		sync_member(&mut tx, scope, *user).await?;
		tx.commit().await.map_err(repo_err)?;
	}
	if !absent.is_empty() || !stale.is_empty() {
		tracing::info!(joined = absent.len(), restated = stale.len(), "scope stream reconciled");
	}
	Ok(())
}

/// The members whose last stated set differs from what they hold now.
async fn stale_members(pool: &PgPool) -> Result<Vec<(String, UserId)>, DomainError> {
	#[derive(sqlx::FromRow)]
	struct Member {
		scope: String,
		user_id: Uuid,
		permissions: Vec<String>,
		namespace: String,
		hold_all: bool,
		role: String,
		targets: Vec<String>,
	}
	let members: Vec<Member> = sqlx::query_as(
		"SELECT m.scope, m.user_id, m.permissions, t.namespace, t.granting_seats_hold_all AS hold_all, u.role, \
		        coalesce(array_agg(g.target ORDER BY g.target) FILTER (WHERE g.target IS NOT NULL), '{}') AS targets \
		 FROM scope_members m \
		 JOIN tenants t ON t.id = m.scope \
		 JOIN users u ON u.id = m.user_id \
		 LEFT JOIN grants g ON g.user_id = m.user_id AND g.namespace = t.namespace AND g.revoked_at IS NULL \
		 GROUP BY m.scope, m.user_id, m.permissions, t.namespace, t.granting_seats_hold_all, u.role \
		 ORDER BY m.scope, m.user_id",
	)
	.fetch_all(pool)
	.await
	.map_err(repo_err)?;
	let catalogs: std::collections::HashMap<String, Catalog> = PgGrants::new(pool.clone()).catalogs().await?.into_iter().map(|t| (t.namespace, t.catalog)).collect();
	let mut stale = Vec::new();
	for member in members {
		let catalog = catalogs.get(&member.namespace);
		let targets = member.targets.iter().map(|t| Target::parse(t)).collect::<Result<Vec<_>, _>>()?;
		if concrete(Role::parse(&member.role)?, member.hold_all, &targets, catalog) != member.permissions {
			stale.push((member.scope, UserId::from_raw(member.user_id)));
		}
	}
	Ok(stale)
}

pub struct PgScopeEvents {
	pool: PgPool,
}

impl PgScopeEvents {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
	position: i64,
	visible: bool,
	event_id: Uuid,
	scope: String,
	kind: String,
	occurred_at: i64,
	sequence: i64,
	user_id: Option<Uuid>,
	auth_subject: Option<String>,
	payload: serde_json::Value,
}

fn decode<T: serde::de::DeserializeOwned>(position: i64, payload: serde_json::Value) -> Result<T, DomainError> {
	serde_json::from_value(payload).map_err(|e| DomainError::Repository(format!("scope_outbox row at position {position} does not decode: {e}")))
}

impl TryFrom<OutboxRow> for ScopeEventRecord {
	type Error = DomainError;

	fn try_from(row: OutboxRow) -> Result<Self, DomainError> {
		let position = row.position;
		let body = match row.kind.as_str() {
			"SCOPE_CHANGED" => {
				let scope: ScopeJson = decode(position, row.payload)?;
				ScopeEventBody::ScopeChanged(ScopeRecord {
					state: domain::scopes::ScopeState::parse(&scope.state)?,
					id: scope.id,
					namespace: scope.namespace,
					parent: scope.parent,
					display_name: scope.display_name,
					origins: scope.origins,
					return_paths: scope.return_paths,
					observers: scope.observers,
					clients: scope
						.clients
						.into_iter()
						.map(|c| ScopeClientRecord {
							client_id: c.client_id,
							audience: c.audience,
							disabled: c.disabled,
						})
						.collect(),
					created_at: scope.created_at,
					version: scope.version,
				})
			}
			"GRANTS_CHANGED" => ScopeEventBody::GrantsChanged(decode::<GrantsJson>(position, row.payload)?.permissions),
			"MEMBER_JOINED" => {
				let m: MemberJson = decode(position, row.payload)?;
				ScopeEventBody::MemberJoined(MemberSnapshot {
					email: m.email,
					email_verified: m.email_verified,
					username: m.username,
					preferred_name: m.preferred_name,
					status: m.status,
					kyc_level: m.kyc_level,
					token_version: m.token_version,
					lifecycle_sequence: m.lifecycle_sequence,
				})
			}
			// A kind a newer binary wrote: served as such, so the consumer halts or parks it
			// by position rather than this reader dropping it.
			other => ScopeEventBody::Unknown(other.to_owned()),
		};
		Ok(Self {
			position,
			visible: row.visible,
			event_id: row.event_id,
			scope: row.scope,
			occurred_at: row.occurred_at,
			sequence: u64::try_from(row.sequence).map_err(|_| DomainError::Repository(format!("scope_outbox row at position {position} has a negative sequence")))?,
			user: row.user_id.zip(row.auth_subject),
			body,
		})
	}
}

#[async_trait]
impl ScopeEventRepository for PgScopeEvents {
	async fn observed_by(&self, client_id: &str, own: &str) -> Result<Vec<String>, DomainError> {
		sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1 OR $2 = ANY(observers) ORDER BY id")
			.bind(own)
			.bind(client_id)
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)
	}

	async fn scan(&self, after: i64, scan: i64, visible: Option<&[String]>) -> Result<Vec<ScopeEventRecord>, DomainError> {
		let rows: Vec<OutboxRow> = sqlx::query_as(
			"SELECT position, ($3::TEXT[] IS NULL OR scope = ANY($3)) AS visible, event_id, scope, kind, occurred_at, sequence, user_id, auth_subject, payload \
			 FROM scope_outbox WHERE position > $1 ORDER BY position LIMIT $2",
		)
		.bind(after)
		.bind(scan)
		.bind(visible)
		.fetch_all(&self.pool)
		.await
		.map_err(repo_err)?;
		rows.into_iter().map(ScopeEventRecord::try_from).collect()
	}
}
