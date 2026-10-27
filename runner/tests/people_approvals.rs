//! The decisions about PEOPLE inside `approvals` (`concierge:owner_admission`,
//! `owner_removal`, `user_suspension`, `user_reinstatement`, `admin_admission`,
//! `second_factor_reset`) against a
//! REAL Postgres: each kind end to end, and the invariants that make them safe to hand the
//! seats to (`docs/SCOPES-AND-APPROVALS.md` §5.3).
//!
//! ⚠️ THIS SUITE OWNS THE OWNER ROSTER, like `approvals.rs` and `governance.rs`: it takes
//! the same session advisory lock, and clears the roster of a database the
//! `CONCIERGE_TEST_DB` marker calls disposable.

use std::sync::{
	Arc,
	atomic::{AtomicI64, Ordering},
};

use concierge::{
	approvals::Approvals,
	authz::BreakGlass,
	governance::Governance,
	infrastructure::{approvals::PgApprovals, db, governance::PgGovernance, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	ports::UserDirectoryRepository,
};
use domain::{
	authz::Role,
	users::{UserId, UserStatus},
};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	Approval, ApprovalState, ApprovalVote, DrainLegacyProposalsRequest, GetApprovalRequest, GetApprovalsRevisionRequest, LegacyProposalKind, LegacyProposalRef, ListPlatformOwnersRequest,
	OpenOwnerAdmissionRequest, ProposePersonDecisionRequest, ResignPlatformOwnershipRequest, VetoApprovalRequest, VoteApprovalRequest, approval_service_server::ApprovalService,
	governance_service_server::GovernanceService, propose_person_decision_request::Subject,
};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::{Code, Request};
use uuid::Uuid;

mod common;

const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
const T0: i64 = 1_900_000_000;
const HOUR: i64 = 60 * 60;

struct Fx {
	pool: PgPool,
	url: String,
	users: Arc<PgUsers>,
	people: Approvals,
	repo: Arc<PgApprovals>,
	governance_repo: Arc<PgGovernance>,
	clock: Arc<AtomicI64>,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 10).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users = Arc::new(PgUsers::new(pool.clone()));
	let catalogs = Arc::new(PgScopeCatalogs::new(pool.clone()));
	let clock = Arc::new(AtomicI64::new(T0));
	let repo = Arc::new(PgApprovals::with_fixed_time(pool.clone(), clock.clone()));
	Some(Fx {
		people: Approvals::new(users.clone(), Arc::new(BreakGlass::new(Vec::new())), repo.clone(), catalogs),
		governance_repo: Arc::new(PgGovernance::new(pool.clone(), "https://example.test/owner-removal".into())),
		repo,
		users,
		pool,
		url,
		clock,
	})
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

fn state(approval: &Approval) -> ApprovalState {
	ApprovalState::try_from(approval.state).unwrap()
}

/// The decisions, named for the RPC that opens each.
#[derive(Clone, Copy, Debug)]
enum Decision {
	Admit,
	Remove,
	Suspend,
	Reinstate,
	Admin,
	ResetSecondFactor,
}

impl Decision {
	fn kind(self) -> &'static str {
		match self {
			Self::Admit => "concierge:owner_admission",
			Self::Remove => "concierge:owner_removal",
			Self::Suspend => "concierge:user_suspension",
			Self::Reinstate => "concierge:user_reinstatement",
			Self::Admin => "concierge:admin_admission",
			Self::ResetSecondFactor => "concierge:second_factor_reset",
		}
	}
}

impl Fx {
	fn at(&self, now: i64) {
		self.clock.store(now, Ordering::SeqCst);
	}

	async fn db_now(&self) -> i64 {
		sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn user(&self, tag: &str) -> UserId {
		self.users.resolve(common::google(tag, true), 0).await.expect("provision").id()
	}

	/// Exactly `n` owners, held until the returned connection drops.
	async fn owners(&self, n: usize) -> (PgConnection, Vec<UserId>) {
		common::assert_disposable_database();
		let mut lock = PgConnection::connect(&self.url).await.expect("a connection for the roster lock");
		sqlx::query("SELECT pg_advisory_lock($1)")
			.bind(ROSTER_LOCK)
			.execute(&mut lock)
			.await
			.expect("take the roster lock");
		sqlx::query("UPDATE users SET role = 'investor' WHERE role = 'owner'")
			.execute(&self.pool)
			.await
			.expect("clear the roster");
		let mut owners = Vec::with_capacity(n);
		for _ in 0..n {
			let id = self.user("owner").await;
			self.users.set_role(id, Role::Owner).await.expect("seat the owner");
			owners.push(id);
		}
		(lock, owners)
	}

	async fn open(&self, who: UserId, decision: Decision, subject: UserId) -> Result<Approval, tonic::Status> {
		let request = ProposePersonDecisionRequest {
			subject: Some(Subject::UserId(subject.to_string())),
			reason: "The owners agreed it on a call".into(),
		};
		let request = as_user(who, request);
		match decision {
			Decision::Admit => self.people.propose_owner_admission(request).await,
			Decision::Remove => self.people.propose_owner_removal(request).await,
			Decision::Suspend => self.people.propose_user_suspension(request).await,
			Decision::Reinstate => self.people.propose_user_reinstatement(request).await,
			Decision::Admin => self.people.propose_admin_admission(request).await,
			Decision::ResetSecondFactor => self.people.propose_second_factor_reset(request).await,
		}
		.map(tonic::Response::into_inner)
	}

	async fn vote(&self, who: UserId, id: &str, vote: ApprovalVote) -> Result<Approval, tonic::Status> {
		self.people
			.vote_approval(as_user(
				who,
				VoteApprovalRequest {
					approval_id: id.into(),
					vote: vote as i32,
				},
			))
			.await
			.map(tonic::Response::into_inner)
	}

	async fn veto(&self, who: UserId, id: &str) -> Result<Approval, tonic::Status> {
		self.people
			.veto_approval(as_user(
				who,
				VetoApprovalRequest {
					approval_id: id.into(),
					reason: "Stop".into(),
				},
			))
			.await
			.map(tonic::Response::into_inner)
	}

	async fn get(&self, who: UserId, id: &str) -> Approval {
		self.people
			.get_approval(as_user(who, GetApprovalRequest { approval_id: id.into() }))
			.await
			.expect("get")
			.into_inner()
	}

	/// Everyone on the roster votes FOR, in order, and the last one's answer is returned.
	async fn carry(&self, voters: &[UserId], id: &str) -> Approval {
		let mut last = None;
		for voter in voters {
			last = Some(self.vote(*voter, id, ApprovalVote::For).await.expect("a roster member votes"));
		}
		last.expect("someone votes")
	}

	/// One pass of the executor, as the background loop runs it, at `now`.
	async fn execute_at(&self, now: i64) {
		self.at(now);
		let mut backoff = concierge::approvals::ExecutorBackoff::default();
		concierge::approvals::execute_due(self.repo.as_ref(), &mut backoff, std::time::Duration::from_secs(30))
			.await
			.expect("an executor pass");
	}

	async fn role(&self, user: UserId) -> Role {
		self.users.find_by_id(user).await.unwrap().unwrap().role()
	}

	async fn row(&self, user: UserId) -> (Role, UserStatus, Option<String>) {
		let user = self.users.find_by_id(user).await.unwrap().unwrap();
		(user.role(), user.status(), user.suspension().map(|s| s.as_str().to_owned()))
	}

	async fn count(&self, sql: &str, id: Uuid) -> i64 {
		sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned())).bind(id).fetch_one(&self.pool).await.unwrap()
	}

	async fn roster_changed_at(&self) -> i64 {
		sqlx::query_scalar("SELECT changed_at FROM platform_roster").fetch_one(&self.pool).await.unwrap()
	}

	async fn proposal_state(&self, id: &str) -> String {
		sqlx::query_scalar("SELECT state FROM approvals WHERE id = $1::uuid")
			.bind(id)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	/// The platform policy change, a PLATFORM decision any owner may open: a bystander that
	/// a change of the owners must void.
	async fn bystander(&self, owner: UserId) -> Approval {
		use evconcierge_contracts::concierge::v1::{PlatformApprovalPolicy, ProposePlatformPolicyChangeRequest};
		self.people
			.propose_platform_policy_change(as_user(
				owner,
				ProposePlatformPolicyChangeRequest {
					policy: Some(PlatformApprovalPolicy {
						version: 0,
						cooldown_secs: 3600,
						roster_changed_at: 0,
					}),
					reason: "A bystander".into(),
				},
			))
			.await
			.expect("a platform policy change opens")
			.into_inner()
	}
}

// ---------------------------------------------------------------------------------
// Each kind, end to end.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_second_factor_reset_passes_on_a_majority_and_leaves_no_factor_no_code_and_no_session() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let subject = fx.user("lost-phone").await;
	let bare = fx.user("no-factor").await;
	fx.at(T0);
	// What an enrolment leaves; the material is never read on this path.
	sqlx::query("INSERT INTO second_factors (id, user_id, kind, label, material, created_at, confirmed_at) VALUES ($1, $2, 'totp', 'Phone', '\\x00', $3, $3)")
		.bind(Uuid::new_v4())
		.bind(subject.raw())
		.bind(T0)
		.execute(&fx.pool)
		.await
		.unwrap();
	sqlx::query("INSERT INTO second_factor_recovery_codes (user_id, digest, created_at) VALUES ($1, $2, $3)")
		.bind(subject.raw())
		.bind(vec![7u8; 32])
		.bind(T0)
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(
		fx.open(owners[0], Decision::ResetSecondFactor, bare).await.unwrap_err().code(),
		Code::FailedPrecondition,
		"nothing to reset"
	);
	let version = fx.users.find_by_id(subject).await.unwrap().unwrap().token_version();

	let reset = fx.open(owners[0], Decision::ResetSecondFactor, subject).await.expect("an owner opens a reset");
	assert_eq!(reset.kind, Decision::ResetSecondFactor.kind());
	assert_eq!((reset.voters.len(), reset.threshold), (3, 2), "more than half of the owners besides the opener");
	fx.carry(&owners[1..3], &reset.id).await;
	fx.execute_at(T0 + 24 * HOUR - 1).await;
	assert_eq!(
		fx.count("SELECT count(*) FROM second_factors WHERE user_id = $1", subject.raw()).await,
		1,
		"nothing inside the veto delay"
	);

	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(state(&fx.get(owners[0], &reset.id).await), ApprovalState::Executed);
	assert_eq!(fx.count("SELECT count(*) FROM second_factors WHERE user_id = $1", subject.raw()).await, 0);
	assert_eq!(fx.count("SELECT count(*) FROM second_factor_recovery_codes WHERE user_id = $1", subject.raw()).await, 0);
	assert_eq!(fx.users.find_by_id(subject).await.unwrap().unwrap().token_version(), version + 1, "every session ends");
	assert_eq!(
		fx.count("SELECT count(*) FROM user_outbox WHERE user_id = $1 AND kind = 'SESSIONS_REVOKED'", subject.raw()).await,
		1,
		"and the money plane starts its cool-off"
	);
	let id = Uuid::parse_str(&reset.id).unwrap();
	assert_eq!(
		fx.count("SELECT count(*) FROM admin_action WHERE approval_id = $1 AND action = 'second_factor_reset_by_approval'", id)
			.await,
		1
	);
	let told: Vec<String> =
		sqlx::query_scalar("SELECT payload->>'event' FROM notification_deliveries d JOIN users u ON u.email = d.recipient WHERE u.id = $1 AND d.kind = 'security_notice'")
			.bind(subject.raw())
			.fetch_all(&fx.pool)
			.await
			.unwrap();
	assert_eq!(told, ["reset"]);
}

#[tokio::test]
async fn an_owner_admission_needs_every_other_owner_and_seats_the_candidate_once() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let candidate = fx.user("candidate").await;
	fx.at(T0);

	let opened = fx.open(owners[0], Decision::Admit, candidate).await.expect("an owner opens it");
	assert_eq!(opened.kind, Decision::Admit.kind());
	assert_eq!(opened.scope, "main");
	assert_eq!(opened.level, evconcierge_contracts::concierge::v1::ApprovalLevel::Platform as i32);
	assert_eq!((opened.voters.len(), opened.threshold), (3, 3), "the other owners, and all of them: unanimity");
	let bystander = fx.bystander(owners[0]).await;

	assert_eq!(state(&fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap()), ApprovalState::Open);
	assert_eq!(
		state(&fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap()),
		ApprovalState::Open,
		"two of three is not enough"
	);
	assert_eq!(state(&fx.vote(owners[3], &opened.id, ApprovalVote::For).await.unwrap()), ApprovalState::Passed);

	fx.execute_at(T0 + 24 * HOUR - 1).await;
	assert_eq!(fx.role(candidate).await, Role::Investor, "nothing is written inside the veto delay");

	let before = fx.roster_changed_at().await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.role(candidate).await, Role::Owner);
	let done = fx.get(owners[0], &opened.id).await;
	assert_eq!(state(&done), ApprovalState::Executed);
	assert!(fx.roster_changed_at().await >= before, "the roster's change is stamped");
	assert_eq!(
		fx.proposal_state(&bystander.id).await,
		"void",
		"a live platform decision is void once the owners change — and this one, executed first, is not"
	);

	let id = Uuid::parse_str(&opened.id).unwrap();
	assert_eq!(
		fx.count("SELECT count(*) FROM admin_action WHERE approval_id = $1 AND action = 'owner_admitted_by_approval'", id)
			.await,
		1
	);
	let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM user_outbox WHERE user_id = $1 AND kind = 'ROLE_CHANGED' AND role = 'owner'")
		.bind(candidate.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(outbox, 1, "the money plane is told, in the same transaction");

	// One decision, one execution.
	fx.execute_at(T0 + 25 * HOUR).await;
	assert_eq!(fx.count("SELECT count(*) FROM admin_action WHERE approval_id = $1", id).await, 1);
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Executed);
}

#[tokio::test]
async fn one_against_ends_an_owner_admission_and_a_majority_is_not_enough() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let candidate = fx.user("candidate").await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Admit, candidate).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	let rejected = fx.vote(owners[3], &opened.id, ApprovalVote::Against).await.unwrap();
	assert_eq!(state(&rejected), ApprovalState::Rejected, "two FOR of three, and still no: a minority never grows the roster");
	fx.execute_at(T0 + 48 * HOUR).await;
	assert_eq!(fx.role(candidate).await, Role::Investor);
}

#[tokio::test]
async fn an_owner_removal_demotes_the_target_who_neither_votes_nor_vetoes() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let target = owners[3];
	fx.at(T0);

	let opened = fx.open(owners[0], Decision::Remove, target).await.expect("an owner opens a removal");
	assert_eq!((opened.voters.len(), opened.threshold), (2, 2), "the owners besides the opener and the target, unanimously");
	assert_eq!(
		fx.vote(target, &opened.id, ApprovalVote::Against).await.unwrap_err().code(),
		Code::PermissionDenied,
		"the target is not on the roster"
	);
	assert_eq!(
		fx.veto(target, &opened.id).await.unwrap_err().code(),
		Code::PermissionDenied,
		"and has no veto over their own seat"
	);
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Open);

	fx.carry(&owners[1..3], &opened.id).await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.row(target).await.0, Role::Investor, "all the way down, as an expulsion always was");
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Executed);
	let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'owner'").fetch_one(&fx.pool).await.unwrap();
	assert_eq!(remaining, 3);
}

/// The case the platform floor skips `concierge:*` proposals for (#196): at three owners
/// the peer set of a removal is exactly one, so two honest owners can remove a bad third.
/// A floor of two after the exclusions would make that owner unremovable.
#[tokio::test]
async fn a_fund_of_three_removes_its_bad_actor_with_one_voter() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let target = owners[2];
	fx.at(T0);

	let opened = fx.open(owners[0], Decision::Remove, target).await.expect("three owners may spare one");
	assert_eq!((opened.voters.len(), opened.threshold), (1, 1), "owners \\ {{opener, target}} is exactly one");

	fx.carry(&owners[1..2], &opened.id).await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.row(target).await.0, Role::Investor);
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Executed);
	let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'owner'").fetch_one(&fx.pool).await.unwrap();
	assert_eq!(remaining, 2, "and the fund lands on two");
}

#[tokio::test]
async fn any_other_owner_vetoes_a_removal() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Remove, owners[3]).await.unwrap();
	fx.carry(&owners[1..3], &opened.id).await;
	let vetoed = fx.veto(owners[1], &opened.id).await.expect("inside the delay an owner stops it");
	assert_eq!(state(&vetoed), ApprovalState::Vetoed);
	fx.execute_at(T0 + 48 * HOUR).await;
	assert_eq!(fx.role(owners[3]).await, Role::Owner);
}

#[tokio::test]
async fn a_suspension_passes_on_a_majority_is_the_owners_verdict_and_a_reinstatement_lifts_it() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let subject = fx.user("subject").await;
	fx.at(T0);

	let suspend = fx.open(owners[0], Decision::Suspend, subject).await.unwrap();
	assert_eq!((suspend.voters.len(), suspend.threshold), (3, 2), "more than half of the owners besides the opener");
	fx.carry(&owners[1..3], &suspend.id).await;
	assert_eq!(state(&fx.get(owners[0], &suspend.id).await), ApprovalState::Passed, "two of three carry it");
	fx.execute_at(T0 + 24 * HOUR).await;
	let (_, status, by) = fx.row(subject).await;
	assert_eq!((status, by.as_deref()), (UserStatus::Disabled, Some("governance")));
	let verbs: Vec<String> = sqlx::query_scalar("SELECT action FROM admin_action WHERE subject_user_id = $1 AND approval_id IS NOT NULL")
		.bind(subject.raw())
		.fetch_all(&fx.pool)
		.await
		.unwrap();
	assert_eq!(verbs, ["suspended_by_approval"]);

	// Lifting the owners' verdict is itself a decision.
	let lift = fx.open(owners[0], Decision::Reinstate, subject).await.expect("a suspended account is exactly who this is about");
	fx.carry(&owners[1..3], &lift.id).await;
	fx.execute_at(T0 + 48 * HOUR).await;
	let (_, status, by) = fx.row(subject).await;
	assert_eq!((status, by), (UserStatus::Active, None));
}

#[tokio::test]
async fn a_reinstatement_lifts_only_what_the_owners_imposed() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let held = fx.user("held").await;
	let free = fx.user("free").await;
	fx.at(T0);
	let action = concierge::infrastructure::users::AdminAction {
		actor: Some(owners[1]),
		action: "held",
		reason: "credential stuffing".into(),
		..Default::default()
	};
	fx.users.hold_user(held, &action, owners[1], fx.db_now().await).await.expect("an owner holds an account");
	for subject in [held, free] {
		let refused = fx.open(owners[0], Decision::Reinstate, subject).await.unwrap_err();
		assert_eq!(refused.code(), Code::FailedPrecondition, "one admin's hold, or nothing to lift: {}", refused.message());
	}
}

#[tokio::test]
async fn an_admin_admission_grants_the_admin_role_and_never_over_an_owner() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Admin, subject).await.unwrap();
	fx.carry(&owners[1..3], &opened.id).await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.role(subject).await, Role::Admin);

	let over_an_owner = fx.open(owners[0], Decision::Admin, owners[1]).await.unwrap_err();
	assert_eq!(
		over_an_owner.code(),
		Code::FailedPrecondition,
		"writing `admin` over `owner` would be an expulsion by another door"
	);
}

// ---------------------------------------------------------------------------------
// The invariants.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn only_an_active_owner_opens_and_nobody_opens_one_about_themselves() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let outsider = fx.user("outsider").await;
	let subject = fx.user("subject").await;
	for decision in [
		Decision::Admit,
		Decision::Remove,
		Decision::Suspend,
		Decision::Reinstate,
		Decision::Admin,
		Decision::ResetSecondFactor,
	] {
		let refused = fx.open(outsider, decision, subject).await.unwrap_err();
		assert_eq!(refused.code(), Code::PermissionDenied, "{decision:?}: {}", refused.message());
	}
	for decision in [Decision::Remove, Decision::Suspend, Decision::Admin, Decision::ResetSecondFactor] {
		let refused = fx.open(owners[0], decision, owners[0]).await.unwrap_err();
		assert_ne!(refused.code(), Code::Ok, "{decision:?}");
		assert!(
			matches!(refused.code(), Code::FailedPrecondition | Code::AlreadyExists | Code::PermissionDenied),
			"{decision:?}: {refused}"
		);
	}
	let candidate_unverified = fx.users.resolve(common::google("unverified", false), 0).await.unwrap().id();
	let refused = fx.open(owners[0], Decision::Admit, candidate_unverified).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition, "a seat is reached by mail: {}", refused.message());
	let refused = fx.open(owners[0], Decision::Admit, owners[1]).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition, "already seated");
}

#[tokio::test]
async fn the_floor_keeps_two_owners_at_open_by_resignation_and_when_the_roster_moves_under_a_decision() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	fx.at(T0);
	let refused = fx.open(owners[0], Decision::Remove, owners[1]).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition, "two owners may not become one: {}", refused.message());

	let resign = |who: UserId, confirm: &str| {
		let confirm = confirm.to_owned();
		let people = &fx.people;
		async move { people.resign_ownership(as_user(who, ResignPlatformOwnershipRequest { confirm_email: confirm })).await }
	};
	let email = |who: UserId| {
		let pool = fx.pool.clone();
		async move {
			sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
				.bind(who.raw())
				.fetch_one(&pool)
				.await
				.unwrap()
		}
	};
	let refused = resign(owners[0], &email(owners[0]).await).await.unwrap_err();
	assert_eq!(
		refused.code(),
		Code::AlreadyExists,
		"resigning is held to the removal's floor, refused as the legacy path refuses it"
	);
	assert_eq!(fx.role(owners[0]).await, Role::Owner);

	// Three owners: one may leave, typed-confirmed; then the floor holds again.
	let third = fx.user("third").await;
	fx.users.set_role(third, Role::Owner).await.unwrap();
	let wrong = resign(third, "someone@else.example").await.unwrap_err();
	assert_eq!(wrong.code(), Code::InvalidArgument);
	let roster = resign(third, &email(third).await).await.expect("three owners may spare one").into_inner();
	assert_eq!(roster.items.len(), 2);
	assert!(roster.below_payout_floor, "two owners cannot reach the payout threshold: a warning, not a rule");
	assert_eq!(fx.role(third).await, Role::Investor);
	let refused = resign(owners[1], &email(owners[1]).await).await.unwrap_err();
	assert_eq!(refused.code(), Code::AlreadyExists);

	// Under a PASSED removal the roster moves: the store voids it instead of carrying it out.
	let (_lock2, owners) = {
		drop(_lock);
		fx.owners(4).await
	};
	let opened = fx.open(owners[0], Decision::Remove, owners[3]).await.unwrap();
	fx.carry(&owners[1..3], &opened.id).await;
	sqlx::query("UPDATE users SET role = 'investor' WHERE id = $1")
		.bind(owners[2].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(
		fx.proposal_state(&opened.id).await,
		"void",
		"the trigger voids a platform decision when the owners change under it"
	);
	fx.execute_at(T0 + 48 * HOUR).await;
	assert_eq!(fx.role(owners[3]).await, Role::Owner, "and nothing was carried out");
}

#[tokio::test]
async fn a_seat_decision_is_void_when_the_candidate_stops_qualifying_before_it_is_carried_out() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let candidate = fx.user("candidate").await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Admit, candidate).await.unwrap();
	fx.carry(&owners[1..3], &opened.id).await;
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
		.bind(candidate.raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	fx.execute_at(T0 + 24 * HOUR).await;
	let done = fx.get(owners[0], &opened.id).await;
	assert_eq!(state(&done), ApprovalState::Void);
	assert_eq!(fx.role(candidate).await, Role::Investor, "an owner seat is never given to an account that no longer qualifies");
}

#[tokio::test]
async fn a_vote_is_the_seat_s_a_held_voter_cannot_carry_a_unanimous_decision() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let candidate = fx.user("candidate").await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Admit, candidate).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	// A hold is one operator's brake, no change of the owners: the holder keeps the role
	// and loses the say.
	let action = concierge::infrastructure::users::AdminAction {
		actor: Some(owners[0]),
		action: "held",
		reason: "credential stuffing".into(),
		..Default::default()
	};
	fx.users.hold_user(owners[3], &action, owners[0], fx.db_now().await).await.expect("an owner holds an owner");
	let held = fx.vote(owners[3], &opened.id, ApprovalVote::For).await.unwrap_err();
	assert_eq!(held.code(), Code::PermissionDenied, "a held owner has no say");
	fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(
		state(&fx.get(owners[0], &opened.id).await),
		ApprovalState::Open,
		"two seated FORs of three: unanimity is not reached"
	);
	fx.execute_at(T0 + 48 * HOUR).await;
	assert_eq!(fx.role(candidate).await, Role::Investor);
}

#[tokio::test]
async fn the_same_decision_cannot_be_opened_twice_while_live_and_the_pause_follows_a_change() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let candidate = fx.user("candidate").await;
	let other = fx.user("other").await;
	fx.at(T0);
	let first = fx.open(owners[0], Decision::Admit, candidate).await.unwrap();
	let again = fx.open(owners[1], Decision::Admit, candidate).await.unwrap_err();
	assert!(
		matches!(again.code(), Code::AlreadyExists | Code::FailedPrecondition),
		"one live decision per kind and account: {again}"
	);
	// Withdrawn, it can be opened afresh.
	fx.people
		.cancel_approval(as_user(owners[0], evconcierge_contracts::concierge::v1::CancelApprovalRequest { approval_id: first.id.clone() }))
		.await
		.expect("the opener withdraws");
	let second = fx.open(owners[0], Decision::Admit, candidate).await.expect("a new decision after the first ended");
	fx.carry(&owners[1..4], &second.id).await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.role(candidate).await, Role::Owner);

	// D24(2): the change of the owners pauses platform decisions for the cool-down in force
	// (another suite of this database may have installed its own).
	let policy = fx
		.people
		.get_platform_approval_policy(as_user(owners[0], evconcierge_contracts::concierge::v1::GetPlatformApprovalPolicyRequest {}))
		.await
		.unwrap()
		.into_inner();
	let cooldown = i64::from(policy.cooldown_secs);
	assert!(cooldown > 0);
	let changed = policy.roster_changed_at;
	fx.at(changed + cooldown - 1);
	let paused = fx.open(owners[0], Decision::Admin, other).await.unwrap_err();
	assert_eq!(paused.code(), Code::FailedPrecondition, "{}", paused.message());
	fx.at(changed + cooldown);
	fx.open(owners[0], Decision::Admin, other).await.expect("the pause is over");
}

#[tokio::test]
async fn an_owner_s_suspension_by_the_owners_changes_the_roster() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Suspend, owners[3]).await.unwrap();
	assert_eq!(opened.voters.len(), 2, "the subject is not asked about their own suspension");
	let bystander = fx.bystander(owners[1]).await;
	fx.carry(&owners[1..3], &opened.id).await;
	let before = fx.roster_changed_at().await;
	fx.execute_at(T0 + 24 * HOUR).await;
	assert_eq!(fx.row(owners[3]).await.2.as_deref(), Some("governance"));
	assert!(fx.roster_changed_at().await >= before);
	assert_eq!(fx.proposal_state(&bystander.id).await, "void", "the trigger on the verdict is not lost");
}

#[tokio::test]
async fn an_approval_suspension_open_lets_the_hold_extend_as_a_legacy_proposal_did() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let now = fx.db_now().await;
	let action = |reason: &str| concierge::infrastructure::users::AdminAction {
		actor: Some(owners[1]),
		action: "held",
		reason: reason.into(),
		..Default::default()
	};
	fx.users.hold_user(subject, &action("first"), owners[1], now).await.expect("a hold");
	let refused = fx.users.hold_user(subject, &action("again"), owners[1], now).await.unwrap_err();
	assert!(matches!(refused, domain::error::DomainError::Forbidden(_)), "a hold is not renewed by holding again");
	fx.open(owners[0], Decision::Suspend, subject).await.expect("the owners are deciding");
	fx.users
		.hold_user(subject, &action("while they decide"), owners[1], now)
		.await
		.expect("the hold extends while the owners decide");
}

#[tokio::test]
async fn the_roster_the_revision_and_the_only_writers_of_the_owner_seat() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	fx.at(T0);

	let roster = fx
		.people
		.list_owners(as_user(owners[0], ListPlatformOwnersRequest {}))
		.await
		.expect("a seat holding the grant permission reads it")
		.into_inner();
	assert_eq!(roster.items.len(), 3);
	assert!(!roster.below_payout_floor);
	let outsider = fx.user("outsider").await;
	assert_eq!(
		fx.people.list_owners(as_user(outsider, ListPlatformOwnersRequest {})).await.unwrap_err().code(),
		Code::PermissionDenied
	);

	let revision = |who: UserId| {
		let people = &fx.people;
		async move { people.get_approvals_revision(as_user(who, GetApprovalsRevisionRequest {})).await.map(|r| r.into_inner().revision) }
	};
	let before = revision(owners[0]).await.unwrap();
	fx.open(owners[0], Decision::Admin, fx.user("subject").await).await.unwrap();
	assert!(revision(owners[0]).await.unwrap() > before, "an opening moves it");
	assert_eq!(revision(outsider).await.unwrap_err().code(), Code::PermissionDenied);
}

/// Who may write the owner seat. Every call site of the aggregate's `set_role`, every raw
/// `SET role` and every insert into `users` in the binary's source is named here: a new
/// writer is a second path to the seat and must be routed through an approval — or argued
/// for in this list. (A database trigger refusing `role = 'owner'` outside the two writers
/// was considered and left out: `update_row` rewrites `role` on every account mutation, genesis
/// and the legacy consilium write it too, and older binaries write beside this one during a
/// rollout, so a trigger would fail closed on paths nobody changed.)
#[test]
fn nothing_else_writes_the_owner_seat() {
	let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	let mut found: std::collections::BTreeMap<&str, Vec<String>> = std::collections::BTreeMap::new();
	let mut stack = vec![src.clone()];
	while let Some(dir) = stack.pop() {
		for entry in std::fs::read_dir(&dir).unwrap() {
			let path = entry.unwrap().path();
			if path.is_dir() {
				stack.push(path);
			} else if path.extension().is_some_and(|e| e == "rs") {
				let text = std::fs::read_to_string(&path).unwrap();
				let name = path.strip_prefix(&src).unwrap().to_string_lossy().into_owned();
				for (needle, label) in [(".set_role(", "set_role"), ("SET role", "sql role"), ("INSERT INTO users", "insert user")] {
					if text.contains(needle) {
						found.entry(label).or_default().push(name.clone());
					}
				}
			}
		}
	}
	for files in found.values_mut() {
		files.sort();
	}
	let get = |label: &str| found.get(label).cloned().unwrap_or_default();
	// The executor of an approval, the legacy consilium (until it goes) and the one
	// request-driven writer, which refuses `owner` and the granting of `admin`.
	assert_eq!(
		get("set_role"),
		["infrastructure/governance.rs", "infrastructure/people.rs", "infrastructure/users.rs"],
		"an aggregate role write"
	);
	assert!(get("sql role").is_empty(), "a raw role write: {:?}", get("sql role"));
	assert_eq!(get("insert user"), ["infrastructure/users.rs"], "a new account is created in one place, as an investor");
}

#[test]
fn the_raw_role_writer_exists_only_for_tests() {
	let ports = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ports.rs")).unwrap();
	let at = ports.find("async fn set_role(").expect("the port declares it");
	assert!(
		ports[..at].trim_end().ends_with("#[cfg(feature = \"test-support\")]"),
		"the binary must not carry a writer that seats anyone as anything"
	);
}

// ---------------------------------------------------------------------------------
// Review: holds, drain, the tally, the floor over standing seats, locks, caps, decoding.
// ---------------------------------------------------------------------------------

fn admin_action(actor: UserId, reason: &str) -> concierge::infrastructure::users::AdminAction {
	concierge::infrastructure::users::AdminAction {
		actor: Some(actor),
		action: "held",
		reason: reason.into(),
		..Default::default()
	}
}

#[tokio::test]
async fn an_expired_decision_does_not_extend_a_hold() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let now = fx.db_now().await;
	fx.users.hold_user(subject, &admin_action(owners[1], "first"), owners[1], now).await.expect("a hold");
	let opened = fx.open(owners[0], Decision::Suspend, subject).await.unwrap();
	fx.users
		.hold_user(subject, &admin_action(owners[1], "while they decide"), owners[1], now)
		.await
		.expect("a LIVE decision lets the hold extend");
	// The decision lapses unvoted: a hold must not stay extendable by a corpse.
	sqlx::query("UPDATE approvals SET created_at = $2 - 300000, expires_at = $2 - 100000 WHERE id = $1::uuid")
		.bind(&opened.id)
		.bind(now)
		.execute(&fx.pool)
		.await
		.unwrap();
	let refused = fx.users.hold_user(subject, &admin_action(owners[1], "forever"), owners[1], now).await.unwrap_err();
	assert!(
		matches!(refused, domain::error::DomainError::Forbidden(_)),
		"an expired decision proves nobody is deciding: {refused}"
	);
}

#[tokio::test]
async fn nobody_holds_the_owners_while_they_decide_on_them_and_the_target_does_not_see_the_tally() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let bystander = fx.user("bystander").await;
	fx.at(T0);
	let target = owners[3];
	let opened = fx.open(owners[0], Decision::Remove, target).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();

	let refused = fx.users.hold_user(bystander, &admin_action(target, "to stall"), target, fx.db_now().await).await.unwrap_err();
	assert!(matches!(refused, domain::error::DomainError::Forbidden(_)), "the target may not hold the deciders: {refused}");

	let seen_by_target = fx.get(target, &opened.id).await;
	assert_eq!(seen_by_target.id, opened.id, "the target knows the decision exists");
	assert!(
		seen_by_target
			.voters
			.iter()
			.all(|v| v.vote == ApprovalVote::Pending as i32 && v.email.is_empty() && v.auth_subject.is_empty()),
		"and not who voted what: {:?}",
		seen_by_target.voters
	);
	let seen_by_peer = fx.get(owners[2], &opened.id).await;
	assert!(seen_by_peer.voters.iter().any(|v| v.vote == ApprovalVote::For as i32), "a decider still sees the tally");
}

#[tokio::test]
async fn the_drain_is_refused_over_a_proposal_about_the_caller_and_holds_its_reason_to_the_text_rules() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let service = Governance::new(
		fx.users.clone(),
		Arc::new(BreakGlass::new(Vec::new())),
		fx.governance_repo.clone(),
		tokio::sync::broadcast::channel(8).0,
	);
	let removal = service
		.open_owner_removal(as_user(
			owners[0],
			evconcierge_contracts::concierge::v1::OpenOwnerRemovalRequest {
				target_user_id: owners[3].to_string(),
				reason: "legacy".into(),
			},
		))
		.await
		.expect("the legacy path opens")
		.into_inner();
	let by = LegacyProposalRef {
		kind: LegacyProposalKind::OwnerRemoval as i32,
		id: removal.id.clone(),
	};
	let drain = |who: UserId, reason: &str| {
		let request = as_user(
			who,
			DrainLegacyProposalsRequest {
				items: vec![by.clone()],
				reason: reason.to_owned(),
			},
		);
		let service = service.clone();
		async move { service.drain_legacy_proposals(request).await }
	};
	assert_eq!(drain(owners[3], "stopping my own removal").await.unwrap_err().code(), Code::PermissionDenied);
	assert_eq!(drain(owners[1], "see https://evil.example").await.unwrap_err().code(), Code::InvalidArgument, "no link");
	assert_eq!(drain(owners[1], "tricky\u{202e}text").await.unwrap_err().code(), Code::InvalidArgument, "no direction override");
	assert_eq!(drain(owners[1], "   ").await.unwrap_err().code(), Code::InvalidArgument);
	let drained = drain(owners[1], "moving to approvals").await.expect("another owner drains it").into_inner();
	assert_eq!(drained.items[0].result, "voided");
}

#[tokio::test]
async fn the_floor_counts_the_seats_that_can_still_decide() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	fx.at(T0);
	// The owners' verdict on C: the seat is kept and has no say.
	sqlx::query("UPDATE users SET status = 'disabled', suspended_by = 'governance' WHERE id = $1")
		.bind(owners[2].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
		.bind(owners[1].raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let resign = fx
		.people
		.resign_ownership(as_user(owners[1], ResignPlatformOwnershipRequest { confirm_email: email }))
		.await
		.unwrap_err();
	assert_eq!(resign.code(), Code::AlreadyExists, "A and B stand: B leaving would leave one voice: {resign}");
	assert_eq!(fx.role(owners[1]).await, Role::Owner);
	let removal = fx.open(owners[0], Decision::Remove, owners[1]).await.unwrap_err();
	assert_eq!(removal.code(), Code::FailedPrecondition, "and so for a removal: {}", removal.message());
	// A temporary hold is counted: it lapses, and one operator's brake must not also freeze the roster.
	sqlx::query("UPDATE users SET status = 'active', suspended_by = NULL WHERE id = $1")
		.bind(owners[2].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	let fourth = fx.user("fourth").await;
	fx.users.set_role(fourth, Role::Owner).await.unwrap();
	fx.users
		.hold_user(owners[2], &admin_action(owners[0], "brake"), owners[0], fx.db_now().await)
		.await
		.expect("a hold");
	fx.open(owners[0], Decision::Remove, owners[1]).await.expect("four seats, one on a hold that lapses: one may go");
}

#[tokio::test]
async fn a_vote_and_an_opening_are_not_queued_behind_the_executor_s_locks() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(4).await;
	let (first, second) = (fx.user("first").await, fx.user("second").await);
	fx.at(T0);
	let live = fx.open(owners[0], Decision::Admin, first).await.unwrap();
	// What the executor holds on the owners while it works: NO KEY UPDATE.
	let mut working = fx.pool.begin().await.unwrap();
	sqlx::query("SELECT id FROM users WHERE role = 'owner' ORDER BY id FOR NO KEY UPDATE")
		.fetch_all(&mut *working)
		.await
		.unwrap();
	let both = async {
		let voted = fx.vote(owners[1], &live.id, ApprovalVote::For).await;
		let opened = fx.open(owners[1], Decision::Admin, second).await;
		(voted, opened)
	};
	let (voted, opened) = tokio::time::timeout(std::time::Duration::from_secs(10), both)
		.await
		.expect("a vote and an opening go through while the executor holds the owners");
	voted.expect("the vote");
	opened.expect("the opening");
	working.rollback().await.unwrap();
}

#[tokio::test]
async fn one_owner_holds_only_a_few_decisions_about_people_open() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	fx.at(T0);
	let mut opened = Vec::new();
	for _ in 0..concierge_cap() {
		let subject = fx.user("subject").await;
		opened.push(fx.open(owners[0], Decision::Suspend, subject).await.expect("within the cap"));
	}
	let one_more = fx.user("one-more").await;
	let refused = fx.open(owners[0], Decision::Suspend, one_more).await.unwrap_err();
	assert_eq!(refused.code(), Code::ResourceExhausted, "{}", refused.message());
	fx.open(owners[1], Decision::Suspend, one_more).await.expect("the cap is the opener's, not the platform's");
	// Withdrawing one frees a place.
	fx.people
		.cancel_approval(as_user(
			owners[0],
			evconcierge_contracts::concierge::v1::CancelApprovalRequest { approval_id: opened[0].id.clone() },
		))
		.await
		.unwrap();
	let again = fx.user("again").await;
	fx.open(owners[0], Decision::Suspend, again).await.expect("a place was freed");
}

fn concierge_cap() -> i64 {
	domain::approvals::MAX_LIVE_PEOPLE_PER_OPENER
}

#[tokio::test]
async fn an_action_this_binary_cannot_read_reads_as_none_and_is_voided_not_executed() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let opened = fx.open(owners[0], Decision::Suspend, subject).await.unwrap();
	fx.carry(&owners[1..3], &opened.id).await;
	sqlx::query("UPDATE approvals SET action = '{\"type\": \"from_a_newer_release\"}'::jsonb WHERE id = $1::uuid")
		.bind(&opened.id)
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(fx.get(owners[0], &opened.id).await.id, opened.id, "it still reads");
	fx.execute_at(T0 + 24 * HOUR).await;
	let done = fx.get(owners[0], &opened.id).await;
	assert_eq!(state(&done), ApprovalState::Void);
	assert_eq!(fx.row(subject).await.1, UserStatus::Active, "nothing was carried out");
}

#[tokio::test]
async fn text_and_standing_are_checked_for_an_admin_too_and_the_audit_names_who_asked() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let ask = |reason: &str, subject: UserId| {
		let request = as_user(
			owners[0],
			ProposePersonDecisionRequest {
				subject: Some(Subject::UserId(subject.to_string())),
				reason: reason.to_owned(),
			},
		);
		let people = &fx.people;
		async move { people.propose_admin_admission(request).await }
	};
	assert_eq!(ask("   ", subject).await.unwrap_err().code(), Code::InvalidArgument, "blank is not a reason");
	assert_eq!(ask("fine\u{200b}print", subject).await.unwrap_err().code(), Code::InvalidArgument, "zero-width is not text");
	let unverified = fx.users.resolve(common::google("unverified", false), 0).await.unwrap().id();
	assert_eq!(ask("An admin", unverified).await.unwrap_err().code(), Code::FailedPrecondition, "an admin's address is proven");

	let opened = ask("An admin", subject).await.unwrap().into_inner();
	fx.carry(&owners[1..3], &opened.id).await;
	fx.execute_at(T0 + 24 * HOUR).await;
	let detail: serde_json::Value = sqlx::query_scalar("SELECT detail FROM admin_action WHERE approval_id = $1::uuid")
		.bind(&opened.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(detail["opened_by"], owners[0].to_string());
}

#[tokio::test]
async fn a_legacy_decision_is_void_once_an_owner_it_never_asked_is_seated() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let candidate = fx.user("candidate").await;
	let newcomer = fx.user("newcomer").await;
	let service = Governance::new(
		fx.users.clone(),
		Arc::new(BreakGlass::new(Vec::new())),
		fx.governance_repo.clone(),
		tokio::sync::broadcast::channel(8).0,
	);
	let admission = service
		.open_owner_admission(as_user(
			owners[0],
			OpenOwnerAdmissionRequest {
				candidate_user_id: candidate.to_string(),
				reason: "legacy".into(),
			},
		))
		.await
		.unwrap()
		.into_inner();
	let vote = |who: UserId| {
		let request = as_user(
			who,
			evconcierge_contracts::concierge::v1::SubmitAdmissionVoteRequest {
				admission_id: admission.id.clone(),
				vote: evconcierge_contracts::concierge::v1::AdmissionVote::Admit as i32,
			},
		);
		let service = service.clone();
		async move { service.submit_admission_vote(request).await }
	};
	vote(owners[1]).await.unwrap();
	// Beside the legacy path, an owner is seated by another door while it is open.
	fx.users.set_role(newcomer, Role::Owner).await.unwrap();
	vote(owners[2]).await.unwrap();
	let state: String = sqlx::query_scalar("SELECT state FROM owner_admission WHERE id = $1::uuid")
		.bind(&admission.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(state, "void", "unanimity of the snapshot must not seat someone the newcomer never agreed to");
	assert_eq!(fx.role(candidate).await, Role::Investor);
}

// ---------------------------------------------------------------------------------
// The window: the freeze and the drain on the legacy service.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn closed_openings_refuse_the_legacy_service_and_the_drain_empties_what_is_open() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let candidate = fx.user("candidate").await;
	let open_service = Governance::new(
		fx.users.clone(),
		Arc::new(BreakGlass::new(Vec::new())),
		fx.governance_repo.clone(),
		tokio::sync::broadcast::channel(8).0,
	);
	let closed_service = Governance::new(
		fx.users.clone(),
		Arc::new(BreakGlass::new(Vec::new())),
		fx.governance_repo.clone(),
		tokio::sync::broadcast::channel(8).0,
	)
	.with_openings_closed(true);
	let open = |service: &Governance| {
		let request = as_user(
			owners[0],
			OpenOwnerAdmissionRequest {
				candidate_user_id: candidate.to_string(),
				reason: "legacy".into(),
			},
		);
		let service = service.clone();
		async move { service.open_owner_admission(request).await }
	};

	let legacy = open(&open_service).await.expect("the legacy path still opens while the freeze is off").into_inner();
	let refused = open(&closed_service).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition);
	assert!(refused.message().contains("ProposeOwnerAdmission"), "{refused}");

	let drain = |items: Vec<LegacyProposalRef>| {
		let request = as_user(
			owners[0],
			DrainLegacyProposalsRequest {
				items,
				reason: "moving to approvals".into(),
			},
		);
		let service = closed_service.clone();
		async move { service.drain_legacy_proposals(request).await.map(tonic::Response::into_inner) }
	};
	let by = |kind: LegacyProposalKind, id: &str| LegacyProposalRef {
		kind: kind as i32,
		id: id.to_owned(),
	};
	let drained = drain(vec![
		by(LegacyProposalKind::OwnerAdmission, &legacy.id),
		by(LegacyProposalKind::OwnerRemoval, &Uuid::new_v4().to_string()),
	])
	.await
	.expect("the drain works while openings are closed");
	assert_eq!(drained.items[0].result, "voided");
	assert_eq!(drained.items[1].result, "not_found");
	let again = drain(vec![by(LegacyProposalKind::OwnerAdmission, &legacy.id)]).await.unwrap();
	assert_eq!(again.items[0].result, "not_open", "an already closed proposal is reported, not changed");
	let state: String = sqlx::query_scalar("SELECT state FROM owner_admission WHERE id = $1::uuid")
		.bind(&legacy.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(state, "void");

	let empty = as_user(owners[0], DrainLegacyProposalsRequest { items: vec![], reason: "x".into() });
	assert_eq!(closed_service.drain_legacy_proposals(empty).await.unwrap_err().code(), Code::InvalidArgument);
	let outsider = fx.user("outsider").await;
	let not_owner = as_user(
		outsider,
		DrainLegacyProposalsRequest {
			items: vec![by(LegacyProposalKind::OwnerAdmission, &legacy.id)],
			reason: "x".into(),
		},
	);
	assert_eq!(closed_service.drain_legacy_proposals(not_owner).await.unwrap_err().code(), Code::PermissionDenied);
}
