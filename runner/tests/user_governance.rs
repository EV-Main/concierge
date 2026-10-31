//! Real-Postgres coverage for the split suspension verb: the hold, its lapse, and who may
//! reinstate.
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set and skip cleanly otherwise. What only a live server can prove is
//! exactly what matters here: that an operator's act, the identity write it causes, the
//! cross-plane `user_outbox` row the money plane pulls and the `admin_action` row all
//! commit together or not at all; that the `suspended_by` column is what decides who may
//! reinstate; and that a hold's lapse is a WRITE, because a projection would never reach
//! the money plane.
//!
//! ⚠️ THIS SUITE OWNS THE OWNER ROSTER, like `governance.rs` and `authz_gate.rs`: who may
//! hold whom is decided from `users.role = 'owner'` globally, so a test cannot scope
//! itself to its own fixtures. It takes the SAME session advisory lock those two take, so
//! the three serialize instead of racing.
//!
//! The clock is an argument to every call, so time is simulated rather than waited on: a
//! hold is reached by passing a later `now`, never by sleeping through 24 hours.

use std::sync::Arc;

mod common;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{
		db,
		grants::PgGrants,
		users::{AdminAction, Audit, PgUsers},
	},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::Role,
	users::{HOLD_COOLDOWN_SECS, HOLD_TTL_SECS, Suspension, UserId, UserStatus},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{DisableUserRequest, HoldUserRequest, ReinstateUserRequest, RevokeTokensRequest, SetKycLevelRequest, user_directory_server::UserDirectory};
use sqlx::{Connection, PgConnection, PgPool, Row};
use tonic::{Code, Request};
use uuid::Uuid;

/// The key `governance.rs` and `authz_gate.rs` serialize on — deliberately the same one.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
/// A clock far past any sweep another test in this binary runs. The sweep is GLOBAL —
/// `lapse_due_holds(now)` releases every hold due by `now` in the database — so a hold
/// placed at a real-world instant can be released by a neighbour's sweep mid-test. A
/// hold placed here is due in 2096 and nobody sweeps that far.
const T_FAR: i64 = 4_000_000_000;

struct Fixture {
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = common::database_url()?;
	common::assert_disposable_database();
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let mut roster_lock = PgConnection::connect(&url).await.expect("a dedicated connection for the roster lock");
	sqlx::query("SELECT pg_advisory_lock($1)")
		.bind(ROSTER_LOCK)
		.execute(&mut roster_lock)
		.await
		.expect("take the roster lock");

	sqlx::query("UPDATE users SET role = 'investor' WHERE role = 'owner'")
		.execute(&pool)
		.await
		.expect("clear the roster");

	Some(Fixture {
		users: Arc::new(PgUsers::new(pool.clone())),
		pool,
		_roster_lock: roster_lock,
	})
}

impl Fixture {
	async fn user(&self) -> UserId {
		self.users.resolve(common::google("ug", true), 0).await.expect("provision").id()
	}

	/// Mint an owner straight through the repository: `SetRole` deliberately refuses to,
	/// and a fixture must not be able to do what the RPC cannot.
	async fn owner(&self) -> UserId {
		let id = self.user().await;
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	/// An admin seat, straight through the repository for the reason `owner` gives.
	async fn admin(&self) -> UserId {
		let id = self.user().await;
		self.users.set_role(id, Role::Admin).await.expect("grant the seat");
		id
	}

	fn directory(&self) -> Directory {
		Directory::new(self.users.clone(), Arc::new(PgGrants::new(self.pool.clone())), Arc::new(BreakGlass::new(Vec::new())))
	}

	async fn reload(&self, id: UserId) -> domain::users::User {
		self.users.find_by_id(id).await.expect("read").expect("the user exists")
	}

	/// The cross-plane kinds emitted for one user, oldest first — what the money plane
	/// will actually pull.
	async fn outbox_kinds(&self, id: UserId) -> Vec<String> {
		sqlx::query("SELECT kind FROM user_outbox WHERE user_id = $1 ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the outbox")
			.iter()
			.map(|r| r.get::<String, _>("kind"))
			.collect()
	}

	/// One operator pulling the brake through the console.
	async fn hold(&self, actor: UserId, target: UserId, reason: &str) -> Result<i64, tonic::Status> {
		self.directory()
			.hold_user(as_user(
				actor,
				HoldUserRequest {
					user_id: target.to_string(),
					reason: reason.into(),
				},
			))
			.await
			.map(|response| response.into_inner().hold_expires_at)
	}

	/// The brake straight through the port at a chosen instant — see `T_FAR`.
	async fn hold_at(&self, actor: UserId, target: UserId, now: i64) -> Result<i64, domain::error::DomainError> {
		let action = AdminAction::by(actor, "held", &Audit::default()).with_reason("credential stuffing");
		self.users
			.hold_user(target, &action, actor, now)
			.await
			.map(|user| user.suspension().and_then(Suspension::hold_expires_at).unwrap())
	}

	/// The `detail` JSON of every `held` row for one subject, oldest first.
	async fn held_details(&self, id: UserId) -> Vec<serde_json::Value> {
		sqlx::query_scalar("SELECT detail FROM admin_action WHERE subject_user_id = $1 AND action = 'held' ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the held rows")
	}

	/// `(action, actor, reason)` for one subject, oldest first.
	async fn audit(&self, id: UserId) -> Vec<(String, Option<Uuid>, String)> {
		sqlx::query("SELECT action, actor_user_id, reason FROM admin_action WHERE subject_user_id = $1 ORDER BY position")
			.bind(id.raw())
			.fetch_all(&self.pool)
			.await
			.expect("read the audit log")
			.iter()
			.map(|r| (r.get("action"), r.get("actor_user_id"), r.get("reason")))
			.collect()
	}

	/// Stamp an account with the owners' verdict without standing up a whole consilium —
	/// the SETUP for the tests that are about what happens afterwards, which is a
	/// different question from how the verdict is reached (covered in
	/// `people_approvals.rs`).
	///
	/// Written straight to the two columns, deliberately: no port method imposes a
	/// governance suspension outside the consilium, and adding one so a fixture could use
	/// it would put a second writer of that state into production code.
	async fn stamp_governance_suspension(&self, id: UserId) {
		sqlx::query("UPDATE users SET status = 'disabled', suspended_by = 'governance', hold_expires_at = NULL WHERE id = $1")
			.bind(id.raw())
			.execute(&self.pool)
			.await
			.expect("impose the verdict");
	}
}

fn as_user<T>(id: UserId, inner: T) -> Request<T> {
	let mut request = Request::new(inner);
	request.extensions_mut().insert(Claims {
		sub: id.to_string(),
		iss: "https://auth.concierge.ev".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
		auth_time: None,
	});
	request
}

// ---------------------------------------------------------------------------------
// The retired verb.
// ---------------------------------------------------------------------------------

/// `DisableUser` meant two things at once and now means neither. The refusal has to name
/// BOTH replacements, because the caller is the only one who knows which they wanted.
#[tokio::test]
async fn disable_user_refuses_and_names_both_halves_of_the_verb() {
	let Some(fx) = setup().await else {
		eprintln!("DATABASE_URL unset — skipping real-DB test");
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx.directory().disable_user(as_user(owner, DisableUserRequest { user_id: target.to_string() })).await.unwrap_err();

	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("HoldUser"), "the emergency half is named: {err}");
	assert!(err.message().contains("ProposeUserSuspension"), "the permanent half is named: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "a refusal changes nothing");
	assert!(fx.audit(target).await.is_empty(), "and records nothing");
}

// ---------------------------------------------------------------------------------
// The hold: instant, one actor, and self-cancelling.
// ---------------------------------------------------------------------------------

/// The whole point of the split, end to end. One operator freezes the account instantly —
/// which is what stops money already queued — and the freeze undoes ITSELF, so the same
/// operator cannot make it permanent.
///
/// The lapse being a WRITE is the load-bearing part: the money plane learns an account is
/// unfrozen only from a `user_outbox` row, so a lapse that were merely projected at read
/// time would release the account here and leave it frozen there, permanently.
#[tokio::test]
async fn a_hold_freezes_instantly_and_lapses_unratified_across_the_bridge() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let held = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "credential stuffing from a new ASN".into(),
			},
		))
		.await
		.expect("one operator may pull the brake")
		.into_inner();

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Disabled);
	assert!(matches!(user.suspension(), Some(Suspension::AdminHold { .. })), "stamped as a hold, not a verdict");
	assert_eq!(user.suspension().unwrap().hold_expires_at(), Some(held.hold_expires_at));
	assert_eq!(fx.outbox_kinds(target).await, ["CREATED", "SUSPENDED"], "the money plane freezes at once");

	let audit = fx.audit(target).await;
	assert_eq!(audit.len(), 1);
	assert_eq!(audit[0].0, "held");
	assert_eq!(audit[0].1, Some(owner.raw()), "the operator is on the record");
	assert_eq!(audit[0].2, "credential stuffing from a new ASN");

	// A minute before the deadline the sweep leaves it alone — the brake is real until it
	// is not.
	// Asserted on THIS target: the sweep is global, and what another test left due by
	// this instant is not this test's business.
	assert!(
		!fx.users.lapse_due_holds(held.hold_expires_at - 60, 10).await.expect("sweep").contains(&target),
		"a hold that is not due must not be released early"
	);
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled);

	// Swept LATE, as the real one always is — it runs on an interval, not at the
	// deadline — so the end it records is asserted against the deadline, not the sweep.
	let lapsed = fx.users.lapse_due_holds(held.hold_expires_at + 300, 10).await.expect("sweep");
	assert!(lapsed.contains(&target), "the deadline released it");

	let user = fx.reload(target).await;
	assert_eq!(user.status(), UserStatus::Active);
	assert_eq!(user.suspension(), None);
	assert_eq!(
		fx.outbox_kinds(target).await,
		["CREATED", "SUSPENDED", "REINSTATED"],
		"the lapse crosses the bridge, or the money plane stays frozen forever"
	);
	assert_eq!(fx.audit(target).await.last().map(|a| a.0.clone()), Some("hold_lapsed".into()));
	assert_eq!(fx.audit(target).await.last().unwrap().1, None, "nobody acted, and the log says so");
	assert_eq!(
		user.hold_ended_at(),
		Some(held.hold_expires_at),
		"the cooldown counts from the deadline, not from the sweep that noticed it"
	);
}

/// A reason is required because the owners asked to ratify a hold are reading exactly
/// this sentence, and a freeze with no stated cause cannot be reviewed by anyone.
#[tokio::test]
async fn a_hold_without_a_reason_is_refused_before_anything_is_written() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "   ".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "{err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
	assert!(fx.audit(target).await.is_empty());
}

/// A hold lapses, and that has to mean something. Pressed again while it is live, the
/// button used to restart the clock — so one admin pressing it daily held an investor
/// indefinitely with no owner asked, or held every other owner out of the votes that
/// could stop it. Now it is refused, the deadline stands, and nothing is written.
#[tokio::test]
async fn a_hold_is_not_renewed_by_holding_again() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let first = fx.hold_at(owner, target, T_FAR).await.expect("the first brake");

	let err = fx.hold(owner, target, "still stuffing").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("ProposeUserSuspension"), "the refusal names the proposal to open instead: {err}");
	assert_eq!(fx.reload(target).await.suspension().unwrap().hold_expires_at(), Some(first), "the deadline did not move");
	assert_eq!(fx.audit(target).await.len(), 1, "a refusal is not an action");
	assert_eq!(fx.outbox_kinds(target).await, ["CREATED", "SUSPENDED"], "and the money plane heard of one freeze");
}

/// After a lapse the next hold waits out `HOLD_COOLDOWN_SECS`, or the lapse would be a
/// formality: a day on, one sweep off, forever. The owners are the only way past it.
#[tokio::test]
async fn a_lapsed_hold_starts_a_cooldown() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	fx.hold_at(owner, target, T_FAR).await.expect("hold");
	// Lifted by one act rather than swept: the sweep is global (see `T_FAR`), and the
	// aggregate records the end the same way for both — the lapse path is proved in
	// `a_hold_freezes_instantly_and_lapses_unratified_across_the_bridge`. Lifted three
	// hours AFTER the deadline, as an operator beating a stalled sweep would: the end
	// is still the deadline, or the cooldown would stretch by however late they were.
	let ended = T_FAR + HOLD_TTL_SECS;
	fx.users.enable_user(target, ended + 3 * 3_600).await.expect("lifted");
	assert_eq!(fx.reload(target).await.hold_ended_at(), Some(ended), "dated at the deadline, not at the lift");

	let err = fx.hold_at(owner, target, ended + HOLD_COOLDOWN_SECS - 1).await.unwrap_err();
	assert!(matches!(err, domain::error::DomainError::Forbidden(_)), "inside the cooldown: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "nothing was written");
	assert_eq!(fx.held_details(target).await.len(), 1, "and no audit row claims otherwise");

	// The console sees the same refusal as a precondition it can act on.
	let err = fx.hold(owner, target, "again").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");

	fx.hold_at(owner, target, ended + HOLD_COOLDOWN_SECS)
		.await
		.expect("the cooldown is over; one actor may brake again");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled);
}

/// The votes on every user proposal need a session, so an admin who could hold the
/// owners could hold them out of the consilium that decides whether the hold stands.
/// Only an owner holds a seat. The refusal names the proposal, and writes nothing.
#[tokio::test]
async fn a_seat_is_held_only_by_an_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let admin = fx.admin().await;
	let another_admin = fx.admin().await;

	for target in [owner, another_admin] {
		let err = fx.hold(admin, target, "silence the roster").await.unwrap_err();
		assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
		assert!(err.message().contains("ProposeUserSuspension"), "{err}");
		assert_eq!(fx.reload(target).await.status(), UserStatus::Active);
		assert!(fx.audit(target).await.is_empty(), "a refusal is not an action");
	}

	// The control over a rogue operator: an owner may hold an admin.
	fx.hold(owner, another_admin, "rogue operator").await.expect("an owner holds a seat");
	assert_eq!(fx.reload(another_admin).await.status(), UserStatus::Disabled);
	fx.users.enable_user(another_admin, T_FAR).await.expect("cleanup — see T_FAR");
}

/// The RPC gate refuses a disabled caller, but it runs before the target's row is
/// locked. Two owners pressing on each other at the same instant each pass that gate
/// and then queue on the other's row — so the actor's status is decided again under
/// the lock, from the row as it is THEN. Driven through the port, which is what the
/// window looks like from the transaction's side: an actor whose row is already held.
#[tokio::test]
async fn an_actor_held_in_the_window_holds_nobody() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let other_owner = fx.owner().await;
	let target = fx.user().await;
	fx.hold_at(owner, other_owner, T_FAR).await.expect("the first press lands");

	let err = fx.hold_at(other_owner, target, T_FAR + 1).await.unwrap_err();
	assert!(matches!(err, domain::error::DomainError::Forbidden(_)), "{err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active, "nothing was written");
	assert!(fx.audit(target).await.is_empty(), "a refusal is not an action");
	fx.users.enable_user(other_owner, T_FAR).await.expect("cleanup — see T_FAR");
}

/// A hold on yourself ends your own session, and with it your ability to explain, lift
/// or ratify it. Refused before anything is read or written.
#[tokio::test]
async fn nobody_holds_their_own_account() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let err = fx.hold(owner, owner, "stepping back").await.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("ProposeUserSuspension"), "{err}");
	assert_eq!(fx.reload(owner).await.status(), UserStatus::Active);
	assert!(fx.audit(owner).await.is_empty());
}

// ---------------------------------------------------------------------------------
// Reinstatement: one act for a hold, the owners' business for their own verdict.
// ---------------------------------------------------------------------------------

/// Without the refusal the suspension consilium is advisory: the owners vote to freeze an
/// account and any one admin presses "reinstate".
#[tokio::test]
async fn reinstate_lifts_a_hold_in_one_act_and_refuses_the_owners_verdict() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let directory = fx.directory();

	directory
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "suspicious sign-in".into(),
			},
		))
		.await
		.expect("hold");

	// A hold is one admin's to lift, because it was one admin's to make.
	directory
		.reinstate_user(as_user(
			owner,
			ReinstateUserRequest {
				user_id: target.to_string(),
				reason: "false positive".into(),
			},
		))
		.await
		.expect("a hold lifts in one act");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Active);

	// The owners' verdict is not.
	fx.stamp_governance_suspension(target).await;
	let err = directory
		.reinstate_user(as_user(
			owner,
			ReinstateUserRequest {
				user_id: target.to_string(),
				reason: "changed my mind".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("ProposeUserReinstatement"), "the refusal points at the proposal: {err}");
	assert_eq!(fx.reload(target).await.status(), UserStatus::Disabled, "the verdict stands");
	assert!(
		!fx.audit(target).await.iter().any(|a| a.2 == "changed my mind"),
		"a refusal writes no audit row, because nothing happened to audit"
	);
}

// ---------------------------------------------------------------------------------
// The audit log the console never had.
// ---------------------------------------------------------------------------------

/// None of these wrote a row before: a KYC level could move and a session could be
/// revoked with no record of who did it or why.
#[tokio::test]
async fn every_operator_decision_lands_in_the_audit_log() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	let directory = fx.directory();

	directory
		.set_kyc_level(as_user(
			owner,
			SetKycLevelRequest {
				user_id: target.to_string(),
				kyc_level: 2,
				reason: "documents verified by hand".into(),
			},
		))
		.await
		.expect("set the level");

	directory
		.revoke_tokens(as_user(
			owner,
			RevokeTokensRequest {
				user_id: target.to_string(),
				reason: "device reported stolen".into(),
			},
		))
		.await
		.expect("revoke");

	let audit = fx.audit(target).await;
	let actions: Vec<&str> = audit.iter().map(|a| a.0.as_str()).collect();
	assert_eq!(actions, ["kyc_level_set", "tokens_revoked"]);
	assert!(audit.iter().all(|a| a.1 == Some(owner.raw())), "every row names the operator");
	assert_eq!(audit[0].2, "documents verified by hand");
	assert_eq!(audit[1].2, "device reported stolen");

	// The detail column records what the action DID, taken from the aggregate after the
	// command rather than from what the caller asked for.
	let detail: serde_json::Value = sqlx::query_scalar("SELECT detail FROM admin_action WHERE subject_user_id = $1 ORDER BY position LIMIT 1")
		.bind(target.raw())
		.fetch_one(&fx.pool)
		.await
		.expect("read the detail");
	assert_eq!(detail["kyc_level"], 2);
}

/// The audit row and the change it describes commit together or not at all — a log that
/// can be missing the entry for a change that happened is a source of false confidence.
#[tokio::test]
async fn a_refused_command_writes_neither_the_change_nor_its_audit_row() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;

	let err = fx
		.directory()
		.set_kyc_level(as_user(
			owner,
			SetKycLevelRequest {
				user_id: target.to_string(),
				kyc_level: 99,
				reason: "a tier the platform does not define".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::InvalidArgument, "{err}");
	assert_eq!(fx.reload(target).await.kyc_level(), 0);
	assert!(fx.audit(target).await.is_empty(), "the rollback took the audit row with it");
}

/// A hold cannot restate the owners' verdict as its own, which would hand one admin the
/// 24h clock that goes with a hold and expire a decision they had no part in.
#[tokio::test]
async fn a_hold_cannot_downgrade_a_governance_suspension() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let target = fx.user().await;
	fx.stamp_governance_suspension(target).await;

	let err = fx
		.directory()
		.hold_user(as_user(
			owner,
			HoldUserRequest {
				user_id: target.to_string(),
				reason: "let me put a clock on this".into(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::AlreadyExists, "{err}");

	let user = fx.reload(target).await;
	assert_eq!(user.suspension(), Some(Suspension::Governance));
	// The sweep selects on `hold_expires_at IS NOT NULL` and nothing else, so a verdict
	// with no deadline is invisible to it. Asserted on the column rather than by running
	// the sweep: `lapse_due_holds` is global, and a far-future sweep here would release
	// every hold the tests beside this one are in the middle of asserting on.
	assert_eq!(user.suspension().unwrap().hold_expires_at(), None, "and no sweep will ever release it");
	let due: bool = sqlx::query_scalar("SELECT hold_expires_at IS NOT NULL FROM users WHERE id = $1")
		.bind(target.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert!(!due);
}
