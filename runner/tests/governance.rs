//! Real-Postgres coverage for the owner seats outside `approvals`: the roster, the mail
//! queue that bypasses notification preferences, and `SetRole`'s refusal to move a seat.
//!
//! These hit a **real** Postgres (no mocks, per the project rules). They run when
//! `DATABASE_URL` is set and skip cleanly otherwise, so a DB-less `cargo test` still
//! passes.
//!
//! ⚠️ THIS SUITE OWNS THE OWNER ROSTER. The rules are decided against `users.role =
//! 'owner'` globally, so a test cannot scope itself to its own fixtures the way
//! `user_directory.rs` does. Each test therefore takes a session-level advisory lock
//! (serializing against concurrent runs and other processes) and demotes every existing
//! owner before minting its own. Point `DATABASE_URL` at a development database.

use std::sync::Arc;

mod common;

use concierge::{
	authz::BreakGlass,
	directory::Directory,
	infrastructure::{db, governance::PgGovernance, grants::PgGrants, notifications::PgNotifications, users::PgUsers},
	ports::{GovernanceMailQueued, GovernanceRepository, NotificationDispatchRepository, NotificationRepository, UserDirectoryRepository},
};
use domain::{authz::Role, users::UserId};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{SetRoleRequest, user_directory_server::UserDirectory};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::{Code, Request};
use uuid::Uuid;

/// Arbitrary, stable key for the session lock this suite serializes on.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
/// A fixed instant, so every assertion about time is exact rather than racy.
const T0: i64 = 1_800_000_000;

struct Fixture {
	governance: Arc<PgGovernance>,
	users: Arc<PgUsers>,
	pool: PgPool,
	/// Holding this connection open holds the advisory lock; dropping it releases.
	_roster_lock: PgConnection,
}

async fn setup() -> Option<Fixture> {
	let url = common::database_url()?;
	// This suite clears the owner registry — a state no API can restore. Never on a
	// database nobody has declared disposable.
	common::assert_disposable_database();
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");

	let mut roster_lock = PgConnection::connect(&url).await.expect("a dedicated connection for the roster lock");
	sqlx::query("SELECT pg_advisory_lock($1)")
		.bind(ROSTER_LOCK)
		.execute(&mut roster_lock)
		.await
		.expect("take the roster lock");

	// A clean roster is a precondition, not a courtesy: the floor and the peer set are
	// both counted from every owner in the database.
	sqlx::query("UPDATE users SET role = 'investor' WHERE role = 'owner'")
		.execute(&pool)
		.await
		.expect("clear the roster");

	Some(Fixture {
		governance: Arc::new(PgGovernance::new(pool.clone())),
		users: Arc::new(PgUsers::new(pool.clone())),
		pool,
		_roster_lock: roster_lock,
	})
}

impl Fixture {
	/// Mint a fresh owner. Every fixture user carries a unique subject, so runs neither
	/// collide nor need a clean database beyond the roster.
	async fn owner(&self) -> UserId {
		let id = self.user().await;
		// Straight through the repository: `UserDirectory.SetRole` deliberately refuses to
		// mint owners, and a fixture must not be able to do what the RPC cannot.
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	/// A provisioned user holding no seat.
	async fn user(&self) -> UserId {
		self.provision(true).await
	}

	/// The same, at an address nobody has proved belongs to them.
	async fn unverified_user(&self) -> UserId {
		self.provision(false).await
	}

	/// A seated owner whose address nobody has proved belongs to them.
	async fn unverified_owner(&self) -> UserId {
		let id = self.unverified_user().await;
		self.users.set_role(id, Role::Owner).await.expect("grant the seat");
		id
	}

	async fn provision(&self, email_verified: bool) -> UserId {
		self.users.resolve(common::google("gov", email_verified), 0).await.expect("provision").id()
	}

	async fn email_of(&self, id: UserId) -> String {
		self.users.find_by_id(id).await.expect("read").expect("user exists").email().as_str().to_owned()
	}

	/// The directory service over the same adapter, with no emergency allowlist.
	fn directory(&self) -> Directory {
		Directory::new(self.users.clone(), Arc::new(PgGrants::new(self.pool.clone())), Arc::new(BreakGlass::new(Vec::new())))
	}

	/// The directory service as an `OWNER_SUBJECTS`-listed operator sees it.
	fn directory_with_break_glass(&self, subject: UserId) -> Directory {
		Directory::new(
			self.users.clone(),
			Arc::new(PgGrants::new(self.pool.clone())),
			Arc::new(BreakGlass::new(vec![subject.to_string()])),
		)
	}

	/// A roster of `n` owners, returned in a stable order.
	async fn roster(&self, n: usize) -> Vec<UserId> {
		let mut owners = Vec::with_capacity(n);
		for _ in 0..n {
			owners.push(self.owner().await);
		}
		owners
	}

	async fn role_of(&self, id: UserId) -> Role {
		self.users.find_by_id(id).await.expect("read").expect("user exists").role()
	}
}

#[tokio::test]
async fn the_roster_lists_every_seat_and_when_it_was_granted() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(4).await;
	let listed = fx.governance.owners().await.expect("roster");
	assert_eq!(listed.len(), 4);
	for owner in &owners {
		assert!(listed.iter().any(|row| row.id == owner.raw()), "every seat is listed");
	}
	assert!(listed.iter().all(|row| row.owner_since > 0), "the roster carries when each seat was granted");
}

/// The governance queue: idempotent by key, and bypassing every notification preference —
/// a security mail a subscriber can silently switch off is not one.
#[tokio::test]
async fn governance_mail_is_deduped_and_ignores_notification_preferences() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let payload = serde_json::json!({ "subject_email": "subject@example.com", "case_id": "case-1", "verdict": "declined" });
	let key = format!("kyc-verdict:{}", Uuid::new_v4());

	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "kyc_verdict_alert", &key, &payload)
			.await
			.expect("first"),
		GovernanceMailQueued::Inserted
	);
	// The subscriber follows nothing and has email switched off; the mail queues anyway.
	sqlx::query("UPDATE notification_subscribers SET email_enabled = FALSE, in_app_enabled = FALSE WHERE user_id = $1")
		.bind(owner.raw())
		.execute(&fx.pool)
		.await
		.expect("switch every channel off");
	let second_key = format!("kyc-verdict:{}", Uuid::new_v4());
	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "kyc_verdict_alert", &second_key, &payload)
			.await
			.expect("muted"),
		GovernanceMailQueued::Inserted
	);

	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "kyc_verdict_alert", &key, &payload)
			.await
			.expect("retry"),
		GovernanceMailQueued::SameMail,
		"an at-least-once caller may retry the same key without sending twice"
	);
	// The same key for another kind, or for somebody else, is not a retry.
	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "approval_request", &key, &payload)
			.await
			.expect("another kind"),
		GovernanceMailQueued::Foreign
	);
	let other = fx.owner().await;
	assert_eq!(
		fx.governance
			.enqueue_mail(other.raw(), "other@example.com", true, "kyc_verdict_alert", &key, &payload)
			.await
			.expect("another recipient"),
		GovernanceMailQueued::Foreign
	);
	assert_eq!(
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_deliveries WHERE dedupe_key IN ($1, $2)")
			.bind(&key)
			.bind(&second_key)
			.fetch_one(&fx.pool)
			.await
			.unwrap(),
		2
	);
}

/// Queueing a governance mail refreshes the recipient's subscriber row, and that row's
/// `email_verified` is what `emit` consults before mailing an ordinary notification. It
/// must carry the identity record's flag: hard-coding `true` there made an owner whose
/// address nobody has proved eligible for every email notification they follow (#65).
#[tokio::test]
async fn a_governance_mail_does_not_verify_the_subscriber_by_itself() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.unverified_owner().await;
	let email = fx.email_of(owner).await;
	let payload = serde_json::json!({ "subject_email": "subject@example.com", "case_id": "case-65", "verdict": "declined" });
	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), &email, false, "kyc_verdict_alert", &format!("kyc-verdict:{}", Uuid::new_v4()), &payload)
			.await
			.expect("queued"),
		GovernanceMailQueued::Inserted
	);
	let (subscriber_id, verified): (Uuid, bool) = sqlx::query_as("SELECT id, email_verified FROM notification_subscribers WHERE user_id = $1")
		.bind(owner.raw())
		.fetch_one(&fx.pool)
		.await
		.expect("the subscriber row the mail refreshed");
	assert!(
		!verified,
		"the subscriber carries the identity record's flag, not the fact that a governance mail was addressed to it"
	);

	// The consequence the flag guards: an ordinary notification on a followed topic
	// reaches the inbox and NOT the mail queue. The row is followed as the mail left
	// it — re-resolving the subscriber here would overwrite the very flag under test.
	let notifications = PgNotifications::new(fx.pool.clone());
	notifications.set_topic_subscription(subscriber_id, "platform:announcements", true, true).await.expect("follow");
	let outcome = notifications
		.emit(
			owner.raw(),
			"platform:announcements",
			"nav",
			"NAV updated",
			"",
			"",
			&format!("nav:{}", Uuid::new_v4()),
			T0,
			domain::scope_catalog::TopicDelivery::OptIn,
		)
		.await
		.expect("emit");
	assert!(outcome.in_app, "the in-app copy is unaffected");
	assert!(!outcome.email, "no email is queued to an address nobody has proved belongs to the owner");
}

/// A delivery the dispatcher gives up on loses its link and code, exactly as one it
/// sends does; a delivery it will retry keeps them, because the retry renders from them.
/// Anyone holding a dump of the table must not be able to act on a still-pending seat
/// through a mail that was never sent (#66).
#[tokio::test]
async fn a_parked_delivery_is_redacted_but_a_retried_one_is_not() {
	let Some(fx) = setup().await else {
		return;
	};
	let owner = fx.owner().await;
	let key = format!("payout-approval:{}", Uuid::new_v4());
	let payload = serde_json::json!({
		"consilium_id": "c-66", "initiator_email": "init@example.com", "amount": "1 USDT",
		"approval_url": "https://example.test/governance/consilium/c-66", "code": "ABCDEFGH",
	});
	assert_eq!(
		fx.governance
			.enqueue_mail(owner.raw(), "relay@example.com", true, "payout_approval", &key, &payload)
			.await
			.expect("queued"),
		GovernanceMailQueued::Inserted
	);
	let delivery_id: i64 = sqlx::query_scalar("SELECT id FROM notification_deliveries WHERE dedupe_key = $1")
		.bind(&key)
		.fetch_one(&fx.pool)
		.await
		.expect("the queued row");
	let dispatch = PgNotifications::new(fx.pool.clone());

	// Attempts left ⇒ rescheduled, and the payload is what the next attempt sends.
	dispatch.mark_failed(delivery_id, "smtp down", 60, 6).await.expect("reschedule");
	let (status, payload_after): (String, serde_json::Value) = sqlx::query_as("SELECT status, payload FROM notification_deliveries WHERE id = $1")
		.bind(delivery_id)
		.fetch_one(&fx.pool)
		.await
		.expect("the row");
	assert_eq!(status, "pending");
	assert_eq!(payload_after, payload, "a retry keeps everything, secrets included");

	// Out of attempts ⇒ parked. The secrets go; what an operator reads stays.
	dispatch.mark_failed(delivery_id, "smtp down", 60, 0).await.expect("park");
	let (status, payload_after): (String, serde_json::Value) = sqlx::query_as("SELECT status, payload FROM notification_deliveries WHERE id = $1")
		.bind(delivery_id)
		.fetch_one(&fx.pool)
		.await
		.expect("the row");
	assert_eq!(status, "failed");
	assert!(payload_after.get("approval_url").is_none(), "the link is gone");
	assert!(payload_after.get("code").is_none(), "and the code that arms it");
	assert_eq!(payload_after["consilium_id"], "c-66", "the rest is kept for the operator who looks at the parked row");
	assert_eq!(payload_after["amount"], "1 USDT");
	let dumped = payload_after.to_string();
	assert!(!dumped.contains("ABCDEFGH") && !dumped.contains("consilium/c-66"), "nothing secret survives in any form");
}

// ---------------------------------------------------------------------------------
// SetRole is no longer a way in or out of ownership.
// ---------------------------------------------------------------------------------

/// The other half of pitfall 21. The consilium is only a control if the bare role edit
/// it replaces is actually closed off.
#[tokio::test]
async fn set_role_refuses_to_mint_or_to_strip_an_owner() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(2).await;
	let candidate = fx.user().await;
	let directory = fx.directory();

	let minted = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "owner".into(),
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(minted.code(), Code::FailedPrecondition, "{minted}");
	assert!(minted.message().contains("ProposeOwnerAdmission"), "the refusal points at the consilium: {minted}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor);

	let stripped = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: owners[1].to_string(),
				role: "investor".into(),
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(stripped.code(), Code::FailedPrecondition, "{stripped}");
	assert_eq!(fx.role_of(owners[1]).await, Role::Owner, "the seat stays");

	// `admin` joined the refusal list, in the GRANTING direction only: the seat carries
	// every identity mutation except role granting, so an operator who can appoint
	// operators can appoint accomplices.
	let appointed = directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "admin".into(),
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(appointed.code(), Code::FailedPrecondition, "{appointed}");
	assert!(appointed.message().contains("ProposeAdminAdmission"), "the refusal points at the consilium: {appointed}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor);

	// Every OTHER role change is untouched — this closes ownership and appointment, not
	// the console.
	directory
		.set_role(as_user(
			owners[0],
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "operator".into(),
				reason: String::new(),
			},
		))
		.await
		.expect("an ordinary role change still works");
	assert_eq!(fx.role_of(candidate).await, Role::Operator);
}

/// The bootstrap carve-out that used to live in `guard_ownership` is GONE, and this is
/// the test that keeps it gone. It seated the second owner directly while the roster was
/// smaller than two — precisely the window in which emergency access is live, so it
/// handed an `OWNER_SUBJECTS`-listed operator a way to build a roster of their own. The
/// first seats now come from the genesis seed, which runs at boot with no request behind
/// it, and `SetRole` refuses `owner` at every roster size including zero.
#[tokio::test]
async fn set_role_refuses_to_seat_an_owner_even_on_an_empty_registry() {
	let Some(fx) = setup().await else {
		return;
	};
	// `setup` leaves the registry empty — the one state the carve-out used to fire in.
	let operator = fx.user().await;
	let candidate = fx.user().await;
	// The caller is authorized by emergency access itself (there is no persisted owner to
	// authorize them), so this is the most permissive caller the plane can ever produce.
	let directory = fx.directory_with_break_glass(operator);

	let err = directory
		.set_role(as_user(
			operator,
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "owner".into(),
				reason: String::new(),
			},
		))
		.await
		.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "{err}");
	assert!(err.message().contains("ProposeOwnerAdmission"), "the refusal points at the consilium: {err}");
	assert_eq!(fx.role_of(candidate).await, Role::Investor, "an empty registry is not a licence to seat anyone");

	// The rest of the console still works on that same authority — emergency access
	// grants `operator`, it just never grants a seat. It does not grant `admin` either
	// any more: appointing one is a proposal, and on an empty registry there is nobody to
	// propose to, which is the correct answer rather than a gap.
	directory
		.set_role(as_user(
			operator,
			SetRoleRequest {
				user_id: candidate.to_string(),
				role: "operator".into(),
				reason: String::new(),
			},
		))
		.await
		.expect("an ordinary role change is exactly what emergency access is for");
	assert_eq!(fx.role_of(candidate).await, Role::Operator);
}

/// A request carrying the verified claims the auth layer would have injected.
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

/// The TOCTOU window `SetRole` used to leave open, closed and pinned.
///
/// The guard used to read the target's role on its own connection and only then open the
/// write transaction. An admission committing in between was invisible to it, so a
/// demotion aimed at the candidate saw `holds_seat = false`, passed both refusals, and
/// then blocked on the row until the consilium committed — stripping the seat it had just
/// granted, with no consilium, no floor check and no audit row. This plane's
/// "exactly two writers of `owner`" invariant was false for the width of that window.
///
/// The race is constructed rather than raced for: a transaction that has already seated
/// the candidate holds their row, the demotion is issued while that lock is held, and the
/// seat is committed underneath it. The demotion cannot answer before the commit lands,
/// so a pass here means the decision was taken from the post-commit row.
#[tokio::test]
async fn set_role_cannot_strip_a_seat_granted_while_it_was_deciding() {
	let Some(fx) = setup().await else {
		return;
	};
	let owners = fx.roster(2).await;
	let candidate = fx.user().await;
	let directory = fx.directory();

	// Stand in for an admission carrying its verdict: the seat is written and the
	// candidate's row held, exactly as `grant_seat` leaves it mid-transaction.
	let url = std::env::var("DATABASE_URL").expect("setup already required it");
	let mut seating = PgConnection::connect(&url).await.expect("a connection for the seating transaction");
	sqlx::query("BEGIN").execute(&mut seating).await.expect("begin");
	sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1")
		.bind(candidate.raw())
		.execute(&mut seating)
		.await
		.expect("seat the candidate, uncommitted");

	let demotion = directory.set_role(as_user(
		owners[0],
		SetRoleRequest {
			user_id: candidate.to_string(),
			role: "investor".into(),
			reason: String::new(),
		},
	));
	let commit = async {
		// Long enough for the demotion to reach the row lock it has to wait on. If it has
		// not got there yet the test still passes — it merely stops being able to catch the
		// old bug — so this can never become a false failure.
		tokio::time::sleep(std::time::Duration::from_millis(250)).await;
		sqlx::query("COMMIT").execute(&mut seating).await.expect("commit the seat");
	};
	let (result, ()) = tokio::join!(demotion, commit);

	let err = result.unwrap_err();
	assert_eq!(err.code(), Code::FailedPrecondition, "the demotion must see the committed seat: {err}");
	assert!(err.message().contains("ProposeOwnerRemoval"), "and be pointed at the consilium: {err}");
	assert_eq!(fx.role_of(candidate).await, Role::Owner, "the seat the consilium granted survives");
}
