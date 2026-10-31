//! Postgres adapter for the owner seats outside `approvals`: the roster, genesis, a
//! resignation, and the mail queue that bypasses notification preferences.
//!
//! Every write path opens with [`lock_governance`], which bumps the single-row
//! `governance_revision` counter. One row, so it totally orders every write that moves a
//! seat — genesis, a resignation and an executed people decision in `approvals` — and
//! `GetApprovalsRevision` moves with it.
//!
//! The seat is written through the SAME helpers `PgUsers` uses
//! ([`super::users::load_for_update`] and friends), so there is one identity writer and one
//! outbox convention, not two.

use async_trait::async_trait;
use domain::{
	authz::Role,
	error::DomainError,
	governance::{MIN_OWNERS, check_floor},
	users::{UserId, UserStatus},
};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::{
	genesis::{GenesisOutcome, GenesisSubject, Resolution, Unseatable, UnseatableReason},
	infrastructure::{notifications, users},
	ports::{GovernanceMailQueued, GovernanceRepository, OwnerGenesisRepository},
};

pub struct PgGovernance {
	pool: PgPool,
}

impl PgGovernance {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

/// One current owner, as the roster surface renders them.
#[derive(Clone, sqlx::FromRow)]
pub struct OwnerRow {
	pub id: Uuid,
	pub email: Option<String>,
	/// Whether that address has been PROVEN to belong to them.
	///
	/// Carried on the roster rather than looked up per owner, because every caller that
	/// mails a roster has to know it — governance mail is refused to an unverified
	/// address, and `web::kyc`'s verdict alert was resolving each owner's record again
	/// solely to ask this one question, on a webhook whose vendor budget is 5 seconds.
	pub email_verified: bool,
	pub display_name: Option<String>,
	pub owner_since: i64,
}

pub(super) fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

/// Bump the revision counter and, by taking its row lock, serialize this transaction
/// against every other governance write. Must be the FIRST statement of any write path.
pub(super) async fn lock_governance(conn: &mut PgConnection) -> Result<i64, DomainError> {
	sqlx::query_scalar::<_, i64>("UPDATE governance_revision SET revision = revision + 1 WHERE id RETURNING revision")
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)
}

/// The roster, locked for the duration of the transaction so a concurrent `SetRole`
/// cannot move it between the snapshot and the decision taken from it.
pub(super) async fn owner_ids_for_update(conn: &mut PgConnection) -> Result<Vec<UserId>, DomainError> {
	// Suspended owners are DELIBERATELY included: ownership is the role, and excluding
	// them would let an admin lower the denominator (and the floor) by suspending people.
	let rows = sqlx::query("SELECT id FROM users WHERE role = 'owner' ORDER BY id FOR UPDATE")
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	rows.iter().map(|r| r.try_get::<Uuid, _>("id").map(UserId::from_raw).map_err(repo_err)).collect()
}

/// Take the seat: the role write and its cross-plane `ROLE_CHANGED` go through the user
/// adapter's own helpers, on THIS transaction.
pub(super) async fn take_seat(conn: &mut PgConnection, target: UserId) -> Result<(), DomainError> {
	let mut user = users::load_for_update(conn, target).await?;
	user.set_role(Role::Investor);
	users::update_row(conn, &user).await?;
	users::drain_outbox(conn, &mut user).await
}

/// Grant the seat, through the SAME identity helpers `take_seat` uses, on THIS
/// transaction — so the role write, its cross-plane `ROLE_CHANGED` and the verdict that
/// authorized it commit together or not at all.
pub(super) async fn grant_seat(conn: &mut PgConnection, candidate: UserId) -> Result<(), DomainError> {
	let mut user = users::load_for_update(conn, candidate).await?;
	user.set_role(Role::Owner);
	users::update_row(conn, &user).await?;
	users::drain_outbox(conn, &mut user).await
}

#[async_trait]
impl OwnerGenesisRepository for PgGovernance {
	/// Genesis: the ONE writer that can turn an empty registry into a fund.
	///
	/// It takes [`lock_governance`] and then [`owner_ids_for_update`], the same two locks
	/// in the same order as every seat write, so a genesis racing a people decision — or
	/// another replica's genesis — is serialized rather than interleaved. Reading the roster BEFORE that lock would let two pods each see an
	/// empty registry and seat it twice.
	///
	/// The seats go through [`grant_seat`], so every founder gets the `ROLE_CHANGED` outbox row the money plane pulls.
	///
	/// Every refusal returns early WITHOUT committing, so the revision bump
	/// [`lock_governance`] performs rolls back with it: a boot that seats nobody leaves
	/// the revision alone.
	async fn seed_owners(&self, subjects: &[GenesisSubject]) -> Result<GenesisOutcome, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_governance(&mut tx).await?;

		let owners = owner_ids_for_update(&mut tx).await?;
		if !owners.is_empty() {
			return Ok(GenesisOutcome::Closed { owners: owners.len() as i64 });
		}

		let mut resolution = Resolution::default();
		for subject in subjects {
			match subject {
				GenesisSubject::Id(id) => {
					// A canonical id IS the identity, so `email_verified` is irrelevant here — the
					// id can only have been read off the very row it names. `status` is not
					// irrelevant: a disabled owner can neither act nor be removed.
					let status = sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id = $1")
						.bind(id.raw())
						.fetch_optional(&mut *tx)
						.await
						.map_err(repo_err)?;
					match status.as_deref() {
						None => remember(&mut resolution.missing_ids, *id),
						Some(status) if status == UserStatus::Active.as_str() => remember(&mut resolution.found, *id),
						Some(_) => resolution.unseatable.push(Unseatable {
							named: id.to_string(),
							reason: UnseatableReason::Disabled,
						}),
					}
				}
				GenesisSubject::Mailbox(mailbox) => {
					// `lower(email)` rather than a bare `=`: both sides are already normalized by
					// `Email::parse`, but a row written before that normalization existed would
					// otherwise be invisible to a list the operator can see is correct. The table
					// is tiny and this runs once per boot, so the unindexed scan costs nothing.
					//
					// The flags come back WITH the rows rather than being filtered in SQL, so a
					// refusal can name which problem the address has instead of looking identical
					// to "nobody has signed in yet".
					let rows = sqlx::query("SELECT id, email_verified, status FROM users WHERE lower(email) = $1 ORDER BY id")
						.bind(mailbox.as_str())
						.fetch_all(&mut *tx)
						.await
						.map_err(repo_err)?;
					let mut seatable: Vec<Uuid> = Vec::new();
					let mut blocked: Option<UnseatableReason> = None;
					for row in &rows {
						let id: Uuid = row.try_get("id").map_err(repo_err)?;
						let verified: bool = row.try_get("email_verified").map_err(repo_err)?;
						let status: String = row.try_get("status").map_err(repo_err)?;
						// AN ADDRESS IS NOT AN IDENTITY. The directory stores whatever the IdP
						// claimed, and an unverified sign-in works on purpose so that nothing
						// downstream trusts the address silently. This is the one path that turns a
						// configured string into a seat, and a seat cannot be taken back, so it
						// resolves only through verified rows.
						if !verified {
							blocked.get_or_insert(UnseatableReason::AddressUnverified);
						} else if status != UserStatus::Active.as_str() {
							blocked = Some(UnseatableReason::Disabled);
						} else {
							seatable.push(id);
						}
					}
					match seatable.as_slice() {
						[] => match blocked {
							Some(reason) => resolution.unseatable.push(Unseatable {
								named: mailbox.as_str().to_owned(),
								reason,
							}),
							None => resolution.missing_mailboxes.push(mailbox.clone()),
						},
						[only] => remember(&mut resolution.found, UserId::from_raw(*only)),
						// Filtering to seatable rows first is what stops an impostor's unverified
						// copy of a founder's address from deadlocking genesis permanently — which,
						// leaving the registry empty, would hold emergency access open indefinitely.
						_ => unreachable!("users_verified_email_idx: one verified account per address"),
					}
				}
			}
		}

		if resolution.found.len() < MIN_OWNERS {
			return Ok(GenesisOutcome::TooFew(resolution));
		}
		for id in &resolution.found {
			grant_seat(&mut tx, *id).await?;
		}
		tx.commit().await.map_err(repo_err)?;
		Ok(GenesisOutcome::Seated(resolution))
	}
}

/// The current owner roster, oldest seat first. Shared with the approvals adapter, which
/// serves the same list from its own service.
pub(super) async fn owner_rows(pool: &PgPool) -> Result<Vec<OwnerRow>, DomainError> {
	// `owner_since` is the last time this plane recorded them BECOMING an owner —
	// the outbox is the only record of when a role changed — falling back to the
	// account's own creation for seats granted before the bridge carried roles.
	sqlx::query_as::<_, OwnerRow>(
		"SELECT u.id, u.email, u.email_verified, COALESCE(NULLIF(u.preferred_name, ''), u.legal_name) AS display_name, \
		        COALESCE((SELECT max(o.occurred_at) FROM user_outbox o \
		                  WHERE o.user_id = u.id AND o.kind = 'ROLE_CHANGED' AND o.role = 'owner'), \
		                 EXTRACT(EPOCH FROM u.created_at)::BIGINT) AS owner_since \
		 FROM users u WHERE u.role = 'owner' ORDER BY owner_since ASC, u.id ASC",
	)
	.fetch_all(pool)
	.await
	.map_err(repo_err)
}

/// Give up a seat: the same floor as a removal.
pub(super) async fn resign_seat(pool: &PgPool, who: UserId) -> Result<(), DomainError> {
	let mut tx = pool.begin().await.map_err(repo_err)?;
	lock_governance(&mut tx).await?;
	let owners = owner_ids_for_update(&mut tx).await?;
	if !owners.contains(&who) {
		return Err(DomainError::Forbidden("you do not hold an owner seat".into()));
	}
	// Leaving voluntarily is subject to the SAME floor as being removed: the last
	// seats are not anyone's to vacate. Counted over seats that can still decide: an owner
	// the owners themselves suspended is on the roster and has no say, so two of them and a
	// resignation must not leave one voice (a temporary hold is counted: it lapses).
	check_floor(owners.len())?;
	let standing: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'owner' AND (status = 'active' OR suspended_by IS DISTINCT FROM 'governance')")
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;
	let leaving_stands: bool = sqlx::query_scalar("SELECT status = 'active' OR suspended_by IS DISTINCT FROM 'governance' FROM users WHERE id = $1")
		.bind(who.raw())
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;
	check_floor(usize::try_from(standing).unwrap_or_default() + usize::from(!leaving_stands))?;

	take_seat(&mut tx, who).await?;
	tx.commit().await.map_err(repo_err)
}

/// Append `id` unless it is already there: the same person may be named twice, once by
/// id and once by mailbox, and they hold one seat either way.
fn remember(ids: &mut Vec<UserId>, id: UserId) {
	if !ids.contains(&id) {
		ids.push(id);
	}
}

#[async_trait]
impl GovernanceRepository for PgGovernance {
	async fn owners(&self) -> Result<Vec<OwnerRow>, DomainError> {
		owner_rows(&self.pool).await
	}

	async fn enqueue_mail(
		&self,
		user_id: Uuid,
		recipient: &str,
		email_verified: bool,
		kind: &str,
		dedupe_key: &str,
		payload: &serde_json::Value,
	) -> Result<GovernanceMailQueued, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		// The upsert OVERWRITES `email_verified`, and `emit` reads it back as "may this
		// address be mailed". Hard-coding `true` here made every governance recipient
		// eligible for ordinary email notifications, verified or not (#65).
		let subscriber = notifications::upsert_subscriber(&mut conn, user_id, recipient, email_verified).await?;
		notifications::enqueue_governance_mail(&mut conn, subscriber.id, recipient, kind, dedupe_key, payload).await
	}
}
