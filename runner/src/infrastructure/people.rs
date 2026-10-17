//! The decisions about PEOPLE inside `approvals`: who may be asked about, and what an
//! executed decision writes (`concierge:owner_admission`, `owner_removal`, `user_suspension`,
//! `user_reinstatement`, `admin_admission`; `docs/SCOPES-AND-APPROVALS.md` §5.3).
//!
//! The effects are the legacy consilia's, written through the SAME identity helpers
//! (`users::load_for_update`, `update_row`, `drain_outbox`), so there is one identity writer
//! and one outbox convention. `Role::Owner` is written here by an executed
//! `concierge:owner_admission` and by genesis, and nowhere else (`UserDirectory.SetRole`
//! refuses it) — besides the legacy `GovernanceService`, which stays until the contract step.
//!
//! LOCKS. An execution takes, in this order: the governance revision (so it serialises with
//! the legacy writers, which take it first), the `users` rows of every owner and of the two
//! accounts named, in id order, and only then the proposal row. A change of the owners
//! takes its `users` row and then the `approvals` rows its trigger voids; taken the other
//! way round the executor and a role change could each hold what the other waits for.

use domain::{
	approvals::{Action, PersonEffect, PersonStanding, person_inapplicable},
	authz::Role,
	error::DomainError,
	users::{UserId, UserStatus},
};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{
	approvals::{repo_err, unseated},
	users::{self, AdminAction},
};
use crate::ports::ApprovalRecord;

/// The facts a decision about `user` is measured against, as the row has them now.
pub(super) async fn standing(conn: &mut PgConnection, user: UserId) -> Result<Option<PersonStanding>, DomainError> {
	let row: Option<(String, String, bool, Option<String>)> = sqlx::query_as("SELECT role, status, email_verified, suspended_by FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_optional(conn)
		.await
		.map_err(repo_err)?;
	row.map(|(role, status, verified, suspended_by)| {
		Ok(PersonStanding {
			role: Role::parse(&role)?,
			active: UserStatus::parse(&status)? == UserStatus::Active,
			verified,
			governance_suspended: suspended_by.as_deref() == Some("governance"),
		})
	})
	.transpose()
}

/// Every persisted owner, and the number of seats (suspended ones included: the floor is
/// over seats, and excluding the suspended would let one admin shrink the roster).
pub(super) async fn owner_ids(conn: &mut PgConnection) -> Result<Vec<UserId>, DomainError> {
	let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE role = 'owner' ORDER BY id")
		.fetch_all(conn)
		.await
		.map_err(repo_err)?;
	Ok(ids.into_iter().map(UserId::from_raw).collect())
}

/// The refusals at open. `owners` is every persisted seat, `active` those who can decide
/// now. Cheap and unlocked: the decision that counts is taken again at execution, under
/// the locks.
pub(super) async fn check_open(conn: &mut PgConnection, action: &Action, owners: &[UserId], active: &[UserId]) -> Result<(), DomainError> {
	let Action::People { effect, user, opened_by } = action else {
		return Ok(());
	};
	let (user, opened_by) = (UserId::from_raw(*user), UserId::from_raw(*opened_by));
	if !active.contains(&opened_by) {
		return Err(DomainError::Forbidden("only an active platform owner opens a decision about a person".into()));
	}
	if user == opened_by {
		return Err(DomainError::Conflict(match effect {
			PersonEffect::RemoveOwner => "resign your own seat (ApprovalService.ResignOwnership) rather than proposing your own removal".into(),
			_ => "you cannot open a decision about yourself".into(),
		}));
	}
	let standing = standing(conn, user).await?.ok_or_else(|| DomainError::Validation("the account does not exist".into()))?;
	match person_inapplicable(*effect, standing, owners.len()) {
		Some(why) => Err(DomainError::Precondition(why.into())),
		None => Ok(()),
	}
}

/// What stands between a passed decision and its effect, now, under the locks: `None` to
/// carry it out, else why it is VOID. `locked` are the `users` rows the caller holds.
pub(super) async fn refusal(
	conn: &mut PgConnection,
	record: &ApprovalRecord,
	effect: PersonEffect,
	user: UserId,
	opened_by: UserId,
	locked: &[UserId],
) -> Result<Option<String>, DomainError> {
	let rows: Vec<(Uuid, bool)> = sqlx::query_as("SELECT id, status = 'active' FROM users WHERE role = 'owner' ORDER BY id")
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	// An owner this transaction does not hold appeared after the rows were taken: its
	// seat could be moving, so nothing is decided on this read. The executor retries.
	if rows.iter().any(|(id, _)| !locked.contains(&UserId::from_raw(*id))) {
		return Err(DomainError::Precondition("the owner roster moved while the decision was being carried out".into()));
	}
	if !rows.iter().any(|(id, active)| *active && *id == opened_by.raw()) {
		return Ok(Some("the owner who asked no longer holds an active seat".into()));
	}
	// A vote is the seat's: the FORs that carried it count only from owners who still hold
	// theirs. The veto window stops a decision whose voters left, but nothing here may
	// rest on that — a seat decision is carried out on the roster as it stands.
	let gone = unseated(conn, record).await?;
	let carried = record
		.decision
		.voters
		.iter()
		.filter(|v| v.vote == domain::approvals::Vote::For && !gone.contains(&v.user_id))
		.count();
	if carried < usize::try_from(record.decision.threshold).unwrap_or(usize::MAX) {
		return Ok(Some("the owners who carried this no longer hold their seats".into()));
	}
	let Some(standing) = standing(conn, user).await? else {
		return Ok(Some("the account is gone".into()));
	};
	Ok(person_inapplicable(effect, standing, rows.len()).map(str::to_owned))
}

/// Write the effect, inside the transaction that records the outcome.
pub(super) async fn apply(conn: &mut PgConnection, record: &ApprovalRecord, effect: PersonEffect, user: UserId, now: i64) -> Result<(), DomainError> {
	let mut subject = users::load_for_update(conn, user).await?;
	match effect {
		PersonEffect::AdmitOwner => subject.set_role(Role::Owner),
		// All the way to `investor`: an expulsion is adversarial, and someone the owners
		// have just voted out should not keep every identity mutation but granting roles.
		PersonEffect::RemoveOwner => subject.set_role(Role::Investor),
		PersonEffect::Suspend => subject.suspend(),
		PersonEffect::Reinstate => subject.enable(now),
		PersonEffect::AdmitAdmin => subject.set_role(Role::Admin),
	}
	users::update_row(conn, &subject).await?;
	users::drain_outbox(conn, &mut subject).await?;
	users::record_action(conn, user, &AdminAction::system(effect.audit_verb()).with_reason(&record.reason).with_approval(record.id), now).await
}
