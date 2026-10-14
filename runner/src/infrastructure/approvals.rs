//! Postgres adapter for approvals (`approvals`, `approval_voters`, `approval_events`;
//! migration 0036, `docs/SCOPES-AND-APPROVALS.md` §5).
//!
//! Every write is ONE transaction that holds the proposal row `FOR UPDATE`, applies the
//! domain transition and appends its history row beside it, so a rolled-back act takes
//! its audit row with it. A write that finds an open proposal past its deadline writes
//! the expiry and commits it even when the act it was asked for is then refused: the
//! expiry is a fact, and the refusal is about it.
//!
//! Opening is serialised per (kind, scope) by a transaction-scoped advisory lock: the
//! rolling 24h window sums every live proposal of the pair, and two proposals opened
//! side by side must see each other or a batch passes under a limit it exceeds together.

use std::collections::HashMap;

use async_trait::async_trait;
use domain::{
	approvals::{self, Decision, Field, FieldValue, MAX_TTL_SECS, Outcome, PLATFORM_DELAY_SECS, PLATFORM_MIN_ROSTER, PLATFORM_QUORUM_BPS, ROLLING_WINDOW_SECS, ScopePolicy, Vote, Voter},
	error::DomainError,
	scope_catalog::ApprovalLevel,
	scopes::{ROOT, ScopeState},
	users::UserId,
};
use sqlx::{PgConnection, PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use crate::ports::{ApprovalActor, ApprovalFilter, ApprovalPerson, ApprovalRecord, ApprovalRepository, ApprovalViewer, NewApproval, Proposed};

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

const COLUMNS: &str = "a.id, a.kind, a.proposer, a.scope, a.level, a.escalated_by, a.state, a.subject_ref, a.fields, a.payload_hash, \
	a.requested_by, rb.auth_subject AS rb_subject, rb.email AS rb_email, a.reason, a.threshold, a.policy_version, a.delay_secs, \
	a.created_at, a.expires_at, a.passed_at, a.executable_at, a.decided_at, a.vetoed_by, vb.auth_subject AS vb_subject, vb.email AS vb_email, \
	a.veto_reason, a.void_reason, a.outcome, a.outcome_detail, a.requested_by_client, a.version";
const FROM: &str = " FROM approvals a LEFT JOIN users rb ON rb.id = a.requested_by LEFT JOIN users vb ON vb.id = a.vetoed_by";

fn level_str(level: ApprovalLevel) -> &'static str {
	match level {
		ApprovalLevel::Platform => "platform",
		ApprovalLevel::Scope => "scope",
	}
}

fn level_of(raw: &str) -> Result<ApprovalLevel, DomainError> {
	match raw {
		"platform" => Ok(ApprovalLevel::Platform),
		"scope" => Ok(ApprovalLevel::Scope),
		other => Err(DomainError::Repository(format!("unknown approval level `{other}`"))),
	}
}

fn unsigned(value: i64, column: &str) -> Result<u64, DomainError> {
	u64::try_from(value).map_err(|_| DomainError::Repository(format!("approvals.{column} is negative")))
}

async fn advisory_lock(conn: &mut PgConnection, key: &str) -> Result<(), DomainError> {
	sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
		.bind(key)
		.execute(conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

/// Rows of `COLUMNS` as records, with their rosters read in one query.
async fn records_of(conn: &mut PgConnection, rows: Vec<PgRow>) -> Result<Vec<ApprovalRecord>, DomainError> {
	let ids: Vec<Uuid> = rows.iter().map(|r| r.try_get("id")).collect::<Result<_, _>>().map_err(repo_err)?;
	let voter_rows = sqlx::query(
		"SELECT v.approval_id, v.user_id, v.vote, v.voted_at, u.auth_subject, u.email FROM approval_voters v JOIN users u ON u.id = v.user_id \
		 WHERE v.approval_id = ANY($1) ORDER BY v.approval_id, v.user_id",
	)
	.bind(&ids)
	.fetch_all(conn)
	.await
	.map_err(repo_err)?;
	let mut rosters: HashMap<Uuid, Vec<(Voter, ApprovalPerson)>> = HashMap::new();
	for row in voter_rows {
		let approval: Uuid = row.try_get("approval_id").map_err(repo_err)?;
		let voter = Voter {
			user_id: UserId::from_raw(row.try_get("user_id").map_err(repo_err)?),
			vote: Vote::parse(row.try_get("vote").map_err(repo_err)?)?,
			voted_at: row.try_get::<Option<i64>, _>("voted_at").map_err(repo_err)?.unwrap_or(0),
		};
		let person = ApprovalPerson {
			auth_subject: row.try_get("auth_subject").map_err(repo_err)?,
			email: row.try_get::<Option<String>, _>("email").map_err(repo_err)?.unwrap_or_default(),
		};
		rosters.entry(approval).or_default().push((voter, person));
	}
	rows.iter()
		.map(|row| {
			let id: Uuid = row.try_get("id").map_err(repo_err)?;
			let (voters, people): (Vec<Voter>, Vec<ApprovalPerson>) = rosters.remove(&id).unwrap_or_default().into_iter().unzip();
			record_of(row, voters, people)
		})
		.collect()
}

fn person(row: &PgRow, subject: &str, email: &str) -> Result<Option<ApprovalPerson>, DomainError> {
	let subject: Option<String> = row.try_get(subject).map_err(repo_err)?;
	let email: Option<String> = row.try_get(email).map_err(repo_err)?;
	Ok(subject.map(|auth_subject| ApprovalPerson {
		auth_subject,
		email: email.unwrap_or_default(),
	}))
}

fn record_of(row: &PgRow, voters: Vec<Voter>, people: Vec<ApprovalPerson>) -> Result<ApprovalRecord, DomainError> {
	let get_i64 = |column: &str| row.try_get::<i64, _>(column).map_err(repo_err);
	let get_opt = |column: &str| row.try_get::<Option<i64>, _>(column).map_err(repo_err);
	let fields: Vec<Field> = serde_json::from_value(row.try_get("fields").map_err(repo_err)?).map_err(|e| DomainError::Repository(format!("stored approval fields are unreadable: {e}")))?;
	let requested_by = match (row.try_get::<Option<Uuid>, _>("requested_by").map_err(repo_err)?, person(row, "rb_subject", "rb_email")?) {
		(Some(id), Some(who)) => Some((UserId::from_raw(id), who)),
		_ => None,
	};
	let outcome = row.try_get::<Option<String>, _>("outcome").map_err(repo_err)?.map(|o| Outcome::parse(&o)).transpose()?;
	let threshold = u32::try_from(row.try_get::<i32, _>("threshold").map_err(repo_err)?).map_err(|_| DomainError::Repository("approvals.threshold is negative".into()))?;
	Ok(ApprovalRecord {
		id: row.try_get("id").map_err(repo_err)?,
		kind: row.try_get("kind").map_err(repo_err)?,
		proposer: row.try_get("proposer").map_err(repo_err)?,
		scope: row.try_get("scope").map_err(repo_err)?,
		level: level_of(row.try_get("level").map_err(repo_err)?)?,
		escalated_by: row.try_get("escalated_by").map_err(repo_err)?,
		subject_ref: row.try_get("subject_ref").map_err(repo_err)?,
		fields,
		payload_hash: row.try_get("payload_hash").map_err(repo_err)?,
		requested_by,
		reason: row.try_get("reason").map_err(repo_err)?,
		voters: people,
		vetoed_by: person(row, "vb_subject", "vb_email")?,
		policy_version: unsigned(get_i64("policy_version")?, "policy_version")?,
		created_at: get_i64("created_at")?,
		requested_by_client: row.try_get("requested_by_client").map_err(repo_err)?,
		decision: Decision {
			state: approvals::ApprovalState::parse(row.try_get("state").map_err(repo_err)?)?,
			threshold,
			voters,
			delay_secs: get_i64("delay_secs")?,
			expires_at: get_i64("expires_at")?,
			passed_at: get_opt("passed_at")?,
			executable_at: get_opt("executable_at")?,
			decided_at: get_opt("decided_at")?,
			vetoed_by: row.try_get::<Option<Uuid>, _>("vetoed_by").map_err(repo_err)?.map(UserId::from_raw),
			veto_reason: row.try_get("veto_reason").map_err(repo_err)?,
			void_reason: row.try_get("void_reason").map_err(repo_err)?,
			outcome,
			outcome_detail: row.try_get("outcome_detail").map_err(repo_err)?,
			version: unsigned(get_i64("version")?, "version")?,
			pending: Vec::new(),
		},
	})
}

async fn load(conn: &mut PgConnection, id: Uuid, for_update: bool) -> Result<Option<ApprovalRecord>, DomainError> {
	let lock = if for_update { " FOR UPDATE OF a" } else { "" };
	let row = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS}{FROM} WHERE a.id = $1{lock}")))
		.bind(id)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	let Some(row) = row else { return Ok(None) };
	Ok(records_of(conn, vec![row]).await?.pop())
}

fn not_found(id: Uuid) -> DomainError {
	DomainError::NotFound {
		entity: "approval",
		id: id.to_string(),
	}
}

/// Write what the decision moved, and one history row per transition it drained.
async fn persist(conn: &mut PgConnection, id: Uuid, decision: &mut Decision, actor: Option<ApprovalActor<'_>>, detail: &serde_json::Value, now: i64) -> Result<(), DomainError> {
	let version = i64::try_from(decision.version).map_err(|_| DomainError::Repository("approval version overflows".into()))?;
	sqlx::query(
		"UPDATE approvals SET state = $2, passed_at = $3, executable_at = $4, decided_at = $5, vetoed_by = $6, veto_reason = $7, void_reason = $8, \
		 outcome = $9, outcome_detail = $10, version = $11 WHERE id = $1",
	)
	.bind(id)
	.bind(decision.state.as_str())
	.bind(decision.passed_at)
	.bind(decision.executable_at)
	.bind(decision.decided_at)
	.bind(decision.vetoed_by.map(|u| u.raw()))
	.bind(&decision.veto_reason)
	.bind(&decision.void_reason)
	.bind(decision.outcome.map(Outcome::as_str))
	.bind(&decision.outcome_detail)
	.bind(version)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	for voter in decision.voters.iter().filter(|v| v.vote != Vote::Pending) {
		sqlx::query("UPDATE approval_voters SET vote = $3, voted_at = $4 WHERE approval_id = $1 AND user_id = $2 AND vote = 'pending'")
			.bind(id)
			.bind(voter.user_id.raw())
			.bind(voter.vote.as_str())
			.bind(voter.voted_at)
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}
	write_events(conn, id, decision, actor, detail, now).await
}

async fn write_events(conn: &mut PgConnection, id: Uuid, decision: &mut Decision, actor: Option<ApprovalActor<'_>>, detail: &serde_json::Value, now: i64) -> Result<(), DomainError> {
	let version = i64::try_from(decision.version).map_err(|_| DomainError::Repository("approval version overflows".into()))?;
	for event in std::mem::take(&mut decision.pending) {
		// Nobody performs a lapse: the expiry is written by whichever act found it due.
		let (person, client, detail) = match (event, actor) {
			(approvals::ApprovalEvent::Expired, _) | (_, None) => (None, String::new(), serde_json::json!({})),
			(_, Some(ApprovalActor::Person(user))) => (Some(user.raw()), String::new(), detail.clone()),
			(_, Some(ApprovalActor::Service(client))) => (None, client.to_owned(), detail.clone()),
		};
		sqlx::query("INSERT INTO approval_events (approval_id, event, actor_user_id, actor_client, version, detail, at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
			.bind(id)
			.bind(event.as_str())
			.bind(person)
			.bind(client)
			.bind(version)
			.bind(detail)
			.bind(now)
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}
	Ok(())
}

/// Commit what `act` moved — and a due expiry found on the way even when `act` was
/// refused — then answer the record as it now stands, or the refusal.
async fn finish(
	mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
	mut record: ApprovalRecord,
	result: Result<(), DomainError>,
	actor: ApprovalActor<'_>,
	detail: serde_json::Value,
	now: i64,
) -> Result<ApprovalRecord, DomainError> {
	let result = if record.decision.pending.is_empty() {
		// Nothing moved: a refusal rolls back, a no-op answers what is stored.
		result?;
		Ok(())
	} else {
		persist(&mut tx, record.id, &mut record.decision, Some(actor), &detail, now).await?;
		result
	};
	let stored = load(&mut tx, record.id, false).await?.ok_or_else(|| not_found(record.id))?;
	tx.commit().await.map_err(repo_err)?;
	result.map(|()| stored)
}

/// The persisted owners: the platform roster. Break-glass seats nobody.
async fn owners(conn: &mut PgConnection) -> Result<Vec<UserId>, DomainError> {
	let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE role = 'owner' ORDER BY id FOR SHARE")
		.fetch_all(conn)
		.await
		.map_err(repo_err)?;
	Ok(ids.into_iter().map(UserId::from_raw).collect())
}

/// The active holders of `<namespace>:admin`: a scope's roster.
async fn scope_admins(conn: &mut PgConnection, namespace: &str) -> Result<Vec<UserId>, DomainError> {
	let ids: Vec<Uuid> = sqlx::query_scalar(
		"SELECT DISTINCT u.id FROM grants g JOIN users u ON u.id = g.user_id \
		 WHERE g.namespace = $1 AND g.target = $1 || ':admin' AND g.revoked_at IS NULL AND u.status = 'active' ORDER BY u.id",
	)
	.bind(namespace)
	.fetch_all(conn)
	.await
	.map_err(repo_err)?;
	Ok(ids.into_iter().map(UserId::from_raw).collect())
}

/// Whether `user` still holds the seat `record`'s roster was drawn from. The roster is
/// frozen so that it cannot be stuffed; it does not keep a removed admin's say — removing
/// one is the containment step and must bite at once (§5.6).
async fn holds_seat(conn: &mut PgConnection, record: &ApprovalRecord, user: UserId) -> Result<bool, DomainError> {
	let query = match record.level {
		ApprovalLevel::Platform => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 'owner')").bind(user.raw()),
		ApprovalLevel::Scope => sqlx::query_scalar(
			"SELECT EXISTS (SELECT 1 FROM grants g JOIN tenants t ON t.namespace = g.namespace JOIN users u ON u.id = g.user_id \
			 WHERE t.id = $2 AND g.user_id = $1 AND g.target = t.namespace || ':admin' AND g.revoked_at IS NULL AND u.status = 'active')",
		)
		.bind(user.raw())
		.bind(record.scope.clone()),
	};
	query.fetch_one(conn).await.map_err(repo_err)
}

async fn user_by_subject(conn: &mut PgConnection, subject: &str) -> Result<Option<Uuid>, DomainError> {
	sqlx::query_scalar("SELECT id FROM users WHERE auth_subject = $1")
		.bind(subject)
		.fetch_optional(conn)
		.await
		.map_err(repo_err)
}

pub struct PgApprovals {
	pool: PgPool,
}

impl PgApprovals {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}

	async fn begin_locked(&self, id: Uuid) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, ApprovalRecord), DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let record = load(&mut tx, id, true).await?.ok_or_else(|| not_found(id))?;
		Ok((tx, record))
	}
}

#[async_trait]
impl ApprovalRepository for PgApprovals {
	async fn propose(&self, new: NewApproval, now: i64) -> Result<Proposed, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		advisory_lock(&mut tx, &format!("approval_dedupe:{}:{}", new.proposer, new.dedupe_key)).await?;
		let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM approvals WHERE proposer = $1 AND dedupe_key = $2")
			.bind(&new.proposer)
			.bind(&new.dedupe_key)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(id) = existing {
			let stored = load(&mut tx, id, false).await?.ok_or_else(|| not_found(id))?;
			let same = stored.kind == new.kind.name
				&& stored.scope == new.scope
				&& stored.subject_ref == new.subject_ref
				&& stored.payload_hash == new.payload_hash
				&& stored.reason == new.reason
				&& stored.requested_by.as_ref().map(|(_, p)| p.auth_subject.as_str()) == new.requested_by.as_deref();
			return if same {
				Ok(Proposed::Existing(stored))
			} else {
				Err(DomainError::Conflict(format!("dedupe_key already names proposal {id}, with different content")))
			};
		}
		advisory_lock(&mut tx, &format!("approval_window:{}:{}", new.kind.name, new.scope)).await?;

		let in_root = new.scope == ROOT;
		let namespace = if in_root {
			None
		} else {
			let row: Option<(String, String)> = sqlx::query_as("SELECT namespace, state FROM tenants WHERE id = $1 FOR SHARE")
				.bind(&new.scope)
				.fetch_optional(&mut *tx)
				.await
				.map_err(repo_err)?;
			let Some((namespace, state)) = row else {
				return Err(DomainError::Validation(format!("unknown scope `{}`", new.scope)));
			};
			let state = ScopeState::parse(&state)?;
			if state != ScopeState::Active {
				return Err(DomainError::Precondition(format!("scope `{}` is {}: nothing new opens in it", new.scope, state.as_str())));
			}
			Some(namespace)
		};

		let requested_by = match &new.requested_by {
			Some(subject) => Some(
				user_by_subject(&mut tx, subject)
					.await?
					.ok_or_else(|| DomainError::Validation("requested_by names no account".into()))?,
			),
			None => None,
		};
		for field in &new.fields {
			if let FieldValue::User(subject) = &field.value
				&& user_by_subject(&mut tx, subject).await?.is_none()
			{
				return Err(DomainError::Validation(format!("field `{}` names no account", field.key)));
			}
		}

		let due: Option<Uuid> = sqlx::query_scalar("SELECT id FROM approvals WHERE kind = $1 AND scope = $2 AND subject_ref = $3 AND state = 'open' AND expires_at <= $4")
			.bind(&new.kind.name)
			.bind(&new.scope)
			.bind(&new.subject_ref)
			.bind(now)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(id) = due {
			let mut stale = load(&mut tx, id, true).await?.ok_or_else(|| not_found(id))?;
			if stale.decision.expire_if_due(now) {
				persist(&mut tx, id, &mut stale.decision, None, &serde_json::json!({}), now).await?;
			}
		}
		let live: Option<Uuid> = sqlx::query_scalar("SELECT id FROM approvals WHERE kind = $1 AND scope = $2 AND subject_ref = $3 AND state IN ('open', 'passed')")
			.bind(&new.kind.name)
			.bind(&new.scope)
			.bind(&new.subject_ref)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(id) = live {
			return Err(DomainError::Conflict(format!("proposal {id} about this subject is still live")));
		}

		let admins = match &namespace {
			Some(namespace) => scope_admins(&mut tx, namespace).await?,
			None => Vec::new(),
		};
		// No policy table yet: every scope is measured against the default until
		// `concierge:scope_policy_change` exists to change one.
		let policy = (!in_root).then(ScopePolicy::default);
		let fired = match &policy {
			Some(policy) if new.kind.level == ApprovalLevel::Scope => {
				let window: Vec<serde_json::Value> = sqlx::query_scalar(
					"SELECT fields FROM approvals WHERE kind = $1 AND scope = $2 AND level = 'scope' AND created_at > $3 \
					 AND (state IN ('passed', 'executed') OR (state = 'open' AND expires_at > $4))",
				)
				.bind(&new.kind.name)
				.bind(&new.scope)
				.bind(now - ROLLING_WINDOW_SECS)
				.bind(now)
				.fetch_all(&mut *tx)
				.await
				.map_err(repo_err)?;
				let window: Vec<Vec<Field>> = window
					.into_iter()
					.map(serde_json::from_value)
					.collect::<Result<_, _>>()
					.map_err(|e| DomainError::Repository(format!("stored approval fields are unreadable: {e}")))?;
				approvals::fired_escalations(&new.kind, &new.fields, policy, &window)
			}
			_ => Vec::new(),
		};
		let resolution = approvals::resolve_level(new.kind.level, in_root, fired, admins.len());
		let policy_version = policy.as_ref().map_or(0, |p| p.version);
		let (roster, quorum_bps, delay_secs, ttl_secs) = match (resolution.level, &policy) {
			(ApprovalLevel::Scope, Some(policy)) => (admins, policy.quorum_bps, policy.delay_secs, policy.ttl_secs.min(MAX_TTL_SECS)),
			(ApprovalLevel::Platform, _) | (ApprovalLevel::Scope, None) => (owners(&mut tx).await?, PLATFORM_QUORUM_BPS, PLATFORM_DELAY_SECS, MAX_TTL_SECS),
		};
		if resolution.level == ApprovalLevel::Platform && roster.len() < PLATFORM_MIN_ROSTER {
			return Err(DomainError::Precondition(format!(
				"fewer than {PLATFORM_MIN_ROSTER} platform owners: nobody may decide for the platform alone"
			)));
		}
		let threshold = approvals::threshold(roster.len(), quorum_bps);
		let mut decision = Decision::open(&roster, threshold, i64::from(delay_secs), now + i64::from(ttl_secs));
		let fields = serde_json::to_value(&new.fields).map_err(|e| DomainError::Repository(format!("approval fields do not encode: {e}")))?;
		let roster_size = i32::try_from(roster.len()).map_err(|_| DomainError::Repository("roster overflows".into()))?;
		let threshold = i32::try_from(threshold).map_err(|_| DomainError::Repository("threshold overflows".into()))?;
		let policy_version = i64::try_from(policy_version).map_err(|_| DomainError::Repository("policy version overflows".into()))?;
		sqlx::query(
			"INSERT INTO approvals (id, kind, proposer, scope, level, escalated_by, subject_ref, fields, payload_hash, requested_by, reason, roster_size, \
			 threshold, policy_version, delay_secs, created_at, expires_at, requested_by_client, dedupe_key) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
		)
		.bind(new.id)
		.bind(&new.kind.name)
		.bind(&new.proposer)
		.bind(&new.scope)
		.bind(level_str(resolution.level))
		.bind(&resolution.escalated_by)
		.bind(&new.subject_ref)
		.bind(fields)
		.bind(&new.payload_hash)
		.bind(requested_by)
		.bind(&new.reason)
		.bind(roster_size)
		.bind(threshold)
		.bind(policy_version)
		.bind(decision.delay_secs)
		.bind(now)
		.bind(decision.expires_at)
		.bind(&new.client)
		.bind(&new.dedupe_key)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;
		let roster_ids: Vec<Uuid> = roster.iter().map(|u| u.raw()).collect();
		sqlx::query("INSERT INTO approval_voters (approval_id, user_id) SELECT $1, unnest($2::uuid[])")
			.bind(new.id)
			.bind(&roster_ids)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		let actor_client = if new.client.is_empty() {
			crate::service_caller::BRIDGE_PUBLISHER
		} else {
			new.client.as_str()
		};
		let detail = serde_json::json!({
			"level": level_str(resolution.level),
			"escalated_by": resolution.escalated_by,
			"roster_size": roster_size,
			"threshold": threshold,
			"dedupe_key": new.dedupe_key,
		});
		write_events(&mut tx, new.id, &mut decision, Some(ApprovalActor::Service(actor_client)), &detail, now).await?;
		let stored = load(&mut tx, new.id, false).await?.ok_or_else(|| not_found(new.id))?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Proposed::Opened(stored))
	}

	async fn viewer(&self, user: UserId) -> Result<ApprovalViewer, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let owner: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 'owner')")
			.bind(user.raw())
			.fetch_one(&mut *conn)
			.await
			.map_err(repo_err)?;
		let admin_of: Vec<String> = sqlx::query_scalar(
			"SELECT DISTINCT t.id FROM grants g JOIN tenants t ON t.namespace = g.namespace \
			 WHERE g.user_id = $1 AND g.revoked_at IS NULL AND g.target = g.namespace || ':admin' ORDER BY t.id",
		)
		.bind(user.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		Ok(ApprovalViewer { user, owner, admin_of })
	}

	async fn find(&self, id: Uuid) -> Result<Option<ApprovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		load(&mut conn, id, false).await
	}

	async fn list(&self, viewer: &ApprovalViewer, filter: &ApprovalFilter, now: i64) -> Result<Vec<ApprovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
			"SELECT {COLUMNS}{FROM} WHERE \
			 ($1 OR a.scope = ANY($2) OR a.requested_by = $3 OR EXISTS (SELECT 1 FROM approval_voters v WHERE v.approval_id = a.id AND v.user_id = $3)) \
			 AND ($4::text IS NULL OR a.scope = $4) \
			 AND ($5::text IS NULL OR (CASE WHEN a.state = 'open' AND a.expires_at <= $6 THEN 'expired' ELSE a.state END) = $5) \
			 AND (NOT $7 OR (a.state = 'open' AND a.expires_at > $6 \
			      AND EXISTS (SELECT 1 FROM approval_voters v WHERE v.approval_id = a.id AND v.user_id = $3 AND v.vote = 'pending'))) \
			 AND ($8::bigint IS NULL OR (a.created_at, a.id) < ($8, $9::uuid)) \
			 ORDER BY a.created_at DESC, a.id DESC LIMIT $10"
		)))
		.bind(viewer.owner)
		.bind(&viewer.admin_of)
		.bind(viewer.user.raw())
		.bind(filter.scope.as_deref())
		.bind(filter.state.map(approvals::ApprovalState::as_str))
		.bind(now)
		.bind(filter.awaiting_my_vote)
		.bind(filter.before.map(|(at, _)| at))
		.bind(filter.before.map(|(_, id)| id))
		.bind(filter.limit)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		records_of(&mut conn, rows).await
	}

	async fn vote(&self, id: Uuid, voter: UserId, vote: Vote, now: i64) -> Result<ApprovalRecord, DomainError> {
		let (mut tx, mut record) = self.begin_locked(id).await?;
		record.decision.expire_if_due(now);
		let result = if record.decision.is_voter(voter) && record.decision.state.is_live() && !holds_seat(&mut tx, &record, voter).await? {
			Err(DomainError::Forbidden("you no longer hold the seat this roster was drawn from".into()))
		} else {
			record.decision.vote(voter, vote, now)
		};
		finish(tx, record, result, ApprovalActor::Person(voter), serde_json::json!({ "vote": vote.as_str() }), now).await
	}

	async fn veto(&self, id: Uuid, by: UserId, reason: &str, now: i64) -> Result<ApprovalRecord, DomainError> {
		let (mut tx, mut record) = self.begin_locked(id).await?;
		record.decision.expire_if_due(now);
		let result = if record.decision.is_voter(by) && record.decision.state.is_live() && !holds_seat(&mut tx, &record, by).await? {
			Err(DomainError::Forbidden("you no longer hold the seat this roster was drawn from".into()))
		} else {
			record.decision.veto(by, reason, now)
		};
		finish(tx, record, result, ApprovalActor::Person(by), serde_json::json!({ "reason": reason }), now).await
	}

	async fn withdraw(&self, id: Uuid, proposer: &str, actor: ApprovalActor<'_>, reason: &str, now: i64) -> Result<ApprovalRecord, DomainError> {
		let (tx, mut record) = self.begin_locked(id).await?;
		if record.proposer != proposer {
			return Err(not_found(id));
		}
		record.decision.expire_if_due(now);
		let result = record.decision.withdraw(now);
		finish(tx, record, result, actor, serde_json::json!({ "reason": reason }), now).await
	}

	async fn pull(&self, proposer: &str, limit: i64, now: i64) -> Result<Vec<ApprovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
			"SELECT {COLUMNS}{FROM} WHERE a.proposer = $1 AND a.state = 'passed' AND a.executable_at <= $2 ORDER BY a.executable_at, a.id LIMIT $3"
		)))
		.bind(proposer)
		.bind(now)
		.bind(limit)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		records_of(&mut conn, rows).await
	}

	async fn report(&self, id: Uuid, proposer: &str, actor: ApprovalActor<'_>, outcome: Outcome, detail: &str, now: i64) -> Result<ApprovalRecord, DomainError> {
		let (tx, mut record) = self.begin_locked(id).await?;
		if record.proposer != proposer {
			return Err(not_found(id));
		}
		record.decision.expire_if_due(now);
		let result = record.decision.report(outcome, detail, now).map(drop);
		finish(tx, record, result, actor, serde_json::json!({ "outcome": outcome.as_str(), "detail": detail }), now).await
	}

	async fn policy(&self, scope: &str) -> Result<Option<ScopePolicy>, DomainError> {
		let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
			.bind(scope)
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(known.then(ScopePolicy::default))
	}
}
