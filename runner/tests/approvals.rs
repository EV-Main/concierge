//! `ApprovalService` and `ApprovalExecutionService` against a REAL Postgres
//! (`docs/SCOPES-AND-APPROVALS.md` §5).
//!
//! Every test registers its own scope (`s_<random>`, namespace = scope id) with a client
//! and a published catalog, so it shares the database with the other suites without
//! reading their proposals. The clock is a value the test moves: a delay or a 72h lifetime
//! is crossed by setting it, never by sleeping.
//!
//! ⚠️ The tests that reach the PLATFORM roster own it: it is every `users.role = 'owner'`
//! in the database, so they clear it under the session advisory lock `governance.rs`,
//! `user_governance.rs` and `authz_gate.rs` take, and only against a database the
//! `CONCIERGE_TEST_DB` marker calls disposable.

use std::sync::{
	Arc,
	atomic::{AtomicI64, Ordering},
};

use concierge::{
	approvals::{ApprovalExecution, Approvals},
	infrastructure::{approvals::PgApprovals, db, relying_parties::PgRelyingParties, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	ports::{RelyingPartyRepository, UserDirectoryRepository},
	scope_catalog::ScopeCatalogs,
	service_caller::ServiceCallers,
};
use domain::{authz::Role, users::UserId};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	Approval, ApprovalAmount, ApprovalEscalation, ApprovalFieldSpec, ApprovalFieldType, ApprovalFieldValue, ApprovalKindSpec, ApprovalLevel, ApprovalOutcome, ApprovalState, ApprovalVote,
	EscalationTest, GetApprovalRequest, GetProposalRequest, GetScopeApprovalPolicyRequest, ListApprovalKindsRequest, ListApprovalsRequest, ProposeRequest, PublishScopeCatalogRequest,
	PullApprovedRequest, ReportOutcomeRequest, VetoApprovalRequest, VoteApprovalRequest, WithdrawProposalRequest, approval_execution_service_server::ApprovalExecutionService,
	approval_field_value::Value, approval_service_server::ApprovalService, scope_catalog_service_server::ScopeCatalogService,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::{Code, Request, metadata::MetadataValue};
use uuid::Uuid;

mod common;

const BRIDGE_TOKEN: &str = "test-bridge-token";
/// The key the roster-owning suites serialize on — deliberately the same one.
const ROSTER_LOCK: i64 = 0x676f_765f_6974; // "gov_it"
const T0: i64 = 1_900_000_000;
const HOUR: i64 = 60 * 60;

struct Fx {
	pool: PgPool,
	url: String,
	users: Arc<PgUsers>,
	rp: PgRelyingParties,
	catalogs: ScopeCatalogs,
	people: Approvals,
	services: ApprovalExecution,
	clock: Arc<AtomicI64>,
}

#[derive(Clone)]
struct Scope {
	id: String,
	client: String,
	secret: String,
}

impl Scope {
	fn kind(&self, name: &str) -> String {
		format!("{}:{name}", self.id)
	}
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 10).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let callers = ServiceCallers::new(Some(BRIDGE_TOKEN.into()), Arc::new(PgRelyingParties::new(pool.clone())));
	let users = Arc::new(PgUsers::new(pool.clone()));
	let catalog_repo = Arc::new(PgScopeCatalogs::new(pool.clone()));
	let clock = Arc::new(AtomicI64::new(T0));
	let repo = Arc::new(PgApprovals::with_fixed_time(pool.clone(), clock.clone()));
	Some(Fx {
		people: Approvals::new(users.clone(), repo.clone(), catalog_repo.clone()),
		services: ApprovalExecution::new(callers.clone(), repo, catalog_repo.clone()),
		catalogs: ScopeCatalogs::new(callers, catalog_repo),
		rp: PgRelyingParties::new(pool.clone()),
		users,
		pool,
		url,
		clock,
	})
}

fn as_client<T>(body: T, scope: &Scope) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("x-ev-client-id", MetadataValue::try_from(scope.client.as_str()).unwrap());
	request
		.metadata_mut()
		.insert("authorization", MetadataValue::try_from(format!("Bearer {}", scope.secret)).unwrap());
	request
}

fn as_bridge<T>(body: T) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {BRIDGE_TOKEN}")).unwrap());
	request
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
	});
	request
}

fn code<T>(result: Result<T, tonic::Status>) -> Option<Code> {
	result.err().map(|status| status.code())
}

fn subject_ref() -> String {
	format!("payment:{}", Uuid::new_v4())
}

fn text(key: &str, value: &str) -> ApprovalFieldValue {
	ApprovalFieldValue {
		key: key.into(),
		value: Some(Value::Text(value.into())),
	}
}

fn amount(value: &str, currency: &str) -> ApprovalFieldValue {
	ApprovalFieldValue {
		key: "amount".into(),
		value: Some(Value::Amount(ApprovalAmount {
			value: value.into(),
			currency: currency.into(),
		})),
	}
}

fn transfer(scope: &Scope, value: &str) -> ProposeRequest {
	ProposeRequest {
		kind: scope.kind("transfer"),
		scope: scope.id.clone(),
		subject_ref: subject_ref(),
		requested_by: String::new(),
		reason: "Monthly rebalance".into(),
		fields: vec![text("to_account", "ops"), amount(value, "USDT")],
		dedupe_key: Uuid::new_v4().to_string(),
	}
}

fn spec(key: &str, field_type: ApprovalFieldType) -> ApprovalFieldSpec {
	ApprovalFieldSpec {
		key: key.into(),
		label: key.into(),
		r#type: field_type as i32,
		required: true,
	}
}

impl Fx {
	fn at(&self, now: i64) {
		self.clock.store(now, Ordering::SeqCst);
	}

	async fn user(&self, tag: &str) -> UserId {
		self.users.resolve(common::google(tag, true), 0).await.expect("provision").id()
	}

	async fn auth_subject(&self, user: UserId) -> String {
		sqlx::query_scalar("SELECT auth_subject FROM users WHERE id = $1")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	/// A scope with one client and a catalog of two kinds: `transfer` (SCOPE, escalating
	/// above 1000 USDT per operation and 5000 USDT a day) and `grant` (PLATFORM).
	async fn scope(&self) -> Scope {
		let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
		let scope = Scope {
			id: format!("s_{tag}"),
			client: format!("c_{tag}"),
			secret: format!("{tag}{tag}{tag}"),
		};
		sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, FALSE, 0)")
			.bind(&scope.id)
			.execute(&self.pool)
			.await
			.expect("register the scope");
		sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, created_at, tenant_id) VALUES ($1, $1, $2, 0, $3)")
			.bind(&scope.client)
			.bind(vec![format!("https://{tag}.test/cb")])
			.bind(&scope.id)
			.execute(&self.pool)
			.await
			.expect("register the client");
		self.rp
			.set_secret_hash(&scope.client, Some(Sha256::digest(scope.secret.as_bytes()).as_slice()), 0)
			.await
			.expect("set the secret");
		let escalation = |parameter: &str, test: EscalationTest, threshold: &str| ApprovalEscalation {
			parameter: parameter.into(),
			field_key: "amount".into(),
			test: test as i32,
			default_threshold: threshold.into(),
			currency: "USDT".into(),
		};
		let kinds = vec![
			ApprovalKindSpec {
				name: scope.kind("transfer"),
				label: "Transfer between accounts".into(),
				description: String::new(),
				level: ApprovalLevel::Scope as i32,
				fields: vec![spec("to_account", ApprovalFieldType::Text), spec("amount", ApprovalFieldType::Amount)],
				escalations: vec![
					escalation("per_operation", EscalationTest::AmountAbove, "1000"),
					escalation("daily", EscalationTest::Rolling24hAmountAbove, "5000"),
				],
				proposer: String::new(),
			},
			ApprovalKindSpec {
				name: scope.kind("grant"),
				label: "Grant holdings".into(),
				description: String::new(),
				level: ApprovalLevel::Platform as i32,
				fields: vec![spec("holder", ApprovalFieldType::User)],
				escalations: vec![],
				proposer: String::new(),
			},
		];
		self.catalogs
			.publish_scope_catalog(as_client(
				PublishScopeCatalogRequest {
					version: 100,
					approval_kinds: kinds,
					notification_topics: vec![],
				},
				&scope,
			))
			.await
			.expect("publish the scope catalog");
		scope
	}

	/// `n` active holders of `<scope>:admin`.
	async fn admins(&self, scope: &Scope, n: usize) -> Vec<UserId> {
		let granter = self.user("granter").await;
		let mut admins = Vec::with_capacity(n);
		for _ in 0..n {
			let admin = self.user("admin").await;
			sqlx::query("INSERT INTO grants (user_id, namespace, target, granted_by, granted_at) VALUES ($1, $2, $2 || ':admin', $3, 0)")
				.bind(admin.raw())
				.bind(&scope.id)
				.bind(granter.raw())
				.execute(&self.pool)
				.await
				.expect("grant the admin alias");
			admins.push(admin);
		}
		admins
	}

	/// Exactly `n` platform owners, held until the returned connection drops.
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

	async fn awaiting(&self, who: UserId, id: &str) -> bool {
		self.people
			.list_approvals(as_user(
				who,
				ListApprovalsRequest {
					awaiting_my_vote: true,
					limit: 100,
					..Default::default()
				},
			))
			.await
			.unwrap()
			.into_inner()
			.approvals
			.into_iter()
			.any(|a| a.id == id)
	}

	async fn propose(&self, scope: &Scope, request: ProposeRequest) -> Approval {
		self.services.propose(as_client(request, scope)).await.expect("propose").into_inner()
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

	async fn pull(&self, scope: &Scope) -> Vec<String> {
		let pulled = self.services.pull_approved(as_client(PullApprovedRequest { limit: 0 }, scope)).await.expect("pull").into_inner();
		pulled.approvals.into_iter().map(|a| a.id).collect()
	}

	async fn report(&self, scope: &Scope, id: &str, outcome: ApprovalOutcome, detail: &str) -> Result<Approval, tonic::Status> {
		self.services
			.report_outcome(as_client(
				ReportOutcomeRequest {
					approval_id: id.into(),
					outcome: outcome as i32,
					detail: detail.into(),
				},
				scope,
			))
			.await
			.map(tonic::Response::into_inner)
	}
}

fn state(approval: &Approval) -> ApprovalState {
	ApprovalState::try_from(approval.state).unwrap()
}

#[tokio::test]
async fn a_scope_proposal_passes_on_more_than_half_waits_out_the_delay_and_is_executed_once() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);

	let opened = fx.propose(&scope, transfer(&scope, "250.5")).await;
	assert_eq!(state(&opened), ApprovalState::Open);
	assert_eq!(opened.level, ApprovalLevel::Scope as i32);
	assert!(opened.escalated_by.is_empty());
	assert_eq!((opened.voters.len(), opened.threshold), (3, 2), "more than half of three admins is two");
	assert_eq!(opened.policy_version, 1);
	assert_eq!(opened.expires_at, T0 + 72 * HOUR);
	assert_eq!(opened.proposer, scope.id);
	assert_eq!(opened.requested_by_client, scope.client);

	let one = fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&one), ApprovalState::Open, "one of three is not more than half");
	assert_eq!(
		fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap().version,
		one.version,
		"the same vote again is a no-op"
	);
	assert_eq!(
		code(fx.vote(admins[0], &opened.id, ApprovalVote::Against).await),
		Some(Code::FailedPrecondition),
		"a vote is final"
	);

	fx.at(T0 + 10);
	let passed = fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&passed), ApprovalState::Passed);
	assert_eq!((passed.passed_at, passed.executable_at), (T0 + 10, T0 + 10 + HOUR), "the scope's default delay is an hour");
	assert_eq!(
		code(fx.vote(admins[2], &opened.id, ApprovalVote::Against).await),
		Some(Code::FailedPrecondition),
		"a passed proposal takes no votes"
	);

	assert!(!fx.pull(&scope).await.contains(&opened.id), "inside the veto window nothing is pullable");
	assert_eq!(code(fx.report(&scope, &opened.id, ApprovalOutcome::Executed, "").await), Some(Code::FailedPrecondition));

	fx.at(T0 + 10 + HOUR);
	assert_eq!(fx.pull(&scope).await, vec![opened.id.clone()]);
	assert_eq!(fx.pull(&scope).await, vec![opened.id.clone()], "a pull claims nothing");

	let executed = fx.report(&scope, &opened.id, ApprovalOutcome::Executed, "").await.unwrap();
	assert_eq!(state(&executed), ApprovalState::Executed);
	assert_eq!(executed.decided_at, T0 + 10 + HOUR);
	let again = fx.report(&scope, &opened.id, ApprovalOutcome::Executed, "retried").await.unwrap();
	assert_eq!((again.version, again.outcome_detail.as_str()), (executed.version, ""), "a repeated report writes nothing");
	assert_eq!(code(fx.report(&scope, &opened.id, ApprovalOutcome::Failed, "boom").await), Some(Code::FailedPrecondition));
	assert!(fx.pull(&scope).await.is_empty());

	let history: Vec<String> = sqlx::query_scalar("SELECT event FROM approval_events WHERE approval_id = $1::uuid ORDER BY id")
		.bind(&opened.id)
		.fetch_all(&fx.pool)
		.await
		.unwrap();
	assert_eq!(history, ["opened", "voted", "voted", "passed", "executed"]);
}

#[tokio::test]
async fn enough_votes_against_reject_it() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	fx.vote(admins[0], &opened.id, ApprovalVote::Against).await.unwrap();
	let rejected = fx.vote(admins[1], &opened.id, ApprovalVote::Against).await.unwrap();
	assert_eq!(state(&rejected), ApprovalState::Rejected, "two against of three leaves the threshold of two out of reach");
}

/// The contract departs from the owner consilia here (§5.2): the person a service names
/// as having asked is information it cannot prove, so they stay on the roster and their
/// vote counts like anyone's. What stops one person acting alone is the threshold over
/// the whole roster and the `sole_admin` escalation, not an exclusion.
#[tokio::test]
async fn the_person_a_service_names_stays_on_the_roster_and_moves_no_quorum() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let asker = fx.auth_subject(admins[0]).await;
	let opened = fx
		.propose(
			&scope,
			ProposeRequest {
				requested_by: asker.clone(),
				..transfer(&scope, "10")
			},
		)
		.await;
	assert_eq!(opened.requested_by, asker);
	let seen = fx
		.people
		.get_approval(as_user(admins[1], GetApprovalRequest { approval_id: opened.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert!(!seen.requested_by_email.is_empty(), "the deciders read who asked");
	assert_eq!((opened.voters.len(), opened.threshold), (2, 2));
	assert_eq!(
		state(&fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap()),
		ApprovalState::Open,
		"the asker alone passes nothing"
	);
	assert_eq!(state(&fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap()), ApprovalState::Passed);

	let mut unknown = transfer(&scope, "10");
	unknown.requested_by = "nobody-at-all".into();
	assert_eq!(code(fx.services.propose(as_client(unknown, &scope)).await), Some(Code::InvalidArgument));
}

#[tokio::test]
async fn a_veto_stops_it_inside_the_delay_and_not_after() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);
	let first = fx.propose(&scope, transfer(&scope, "10")).await;
	let second = fx.propose(&scope, transfer(&scope, "10")).await;
	for id in [&first.id, &second.id] {
		fx.vote(admins[0], id, ApprovalVote::For).await.unwrap();
		fx.vote(admins[1], id, ApprovalVote::For).await.unwrap();
	}
	let veto = |id: &str, by: UserId, reason: &str| {
		fx.people.veto_approval(as_user(
			by,
			VetoApprovalRequest {
				approval_id: id.into(),
				reason: reason.into(),
			},
		))
	};
	assert_eq!(code(veto(&first.id, admins[2], "").await), Some(Code::InvalidArgument), "a veto states why");

	fx.at(T0 + HOUR - 1);
	let vetoed = veto(&first.id, admins[2], "The destination is wrong").await.unwrap().into_inner();
	assert_eq!(state(&vetoed), ApprovalState::Vetoed, "one roster member who voted nothing stops what two passed");
	assert_eq!(vetoed.vetoed_by, fx.auth_subject(admins[2]).await);
	assert_eq!(vetoed.veto_reason, "The destination is wrong");

	fx.at(T0 + HOUR);
	assert_eq!(
		code(veto(&second.id, admins[2], "Too late").await),
		Some(Code::FailedPrecondition),
		"past the delay the proposer owns it"
	);
	assert_eq!(fx.pull(&scope).await, vec![second.id.clone()], "the vetoed one is never served");
}

#[tokio::test]
async fn an_open_proposal_expires_lazily_and_frees_its_subject() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let request = transfer(&scope, "10");
	let opened = fx.propose(&scope, request.clone()).await;

	let again = ProposeRequest {
		dedupe_key: Uuid::new_v4().to_string(),
		..request.clone()
	};
	assert_eq!(
		code(fx.services.propose(as_client(again.clone(), &scope)).await),
		Some(Code::AlreadyExists),
		"one subject is decided once at a time"
	);

	fx.at(T0 + 72 * HOUR);
	let read = fx
		.people
		.get_approval(as_user(admins[0], GetApprovalRequest { approval_id: opened.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(
		(state(&read), read.decided_at),
		(ApprovalState::Expired, T0 + 72 * HOUR),
		"read as expired before anything wrote so"
	);
	let stored: String = sqlx::query_scalar("SELECT state FROM approvals WHERE id = $1::uuid")
		.bind(&opened.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(stored, "open", "a read writes nothing");

	assert_eq!(code(fx.vote(admins[0], &opened.id, ApprovalVote::For).await), Some(Code::FailedPrecondition));
	let stored: String = sqlx::query_scalar("SELECT state FROM approvals WHERE id = $1::uuid")
		.bind(&opened.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(stored, "expired", "the refused vote still wrote the expiry it found");

	let reopened = fx.propose(&scope, again).await;
	assert_ne!(reopened.id, opened.id, "an expired proposal no longer holds its subject");
}

#[tokio::test]
async fn an_amount_above_the_threshold_goes_to_the_platform_owners() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 3).await;
	fx.at(T0);

	let big = fx.propose(&scope, transfer(&scope, "1000.000000000000000001")).await;
	assert_eq!(big.level, ApprovalLevel::Platform as i32);
	assert_eq!(big.escalated_by, vec!["per_operation".to_owned()]);
	let seen = fx
		.people
		.get_approval(as_user(owners[0], GetApprovalRequest { approval_id: big.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	let roster: Vec<String> = seen.voters.iter().map(|v| v.auth_subject.clone()).collect();
	for owner in &owners {
		assert!(roster.contains(&fx.auth_subject(*owner).await), "the roster is the owners");
	}
	assert_eq!((big.voters.len(), big.threshold), (3, 2));

	let other = fx
		.propose(
			&scope,
			ProposeRequest {
				fields: vec![text("to_account", "ops"), amount("1", "USDC")],
				..transfer(&scope, "1")
			},
		)
		.await;
	assert_eq!(
		other.escalated_by,
		vec!["per_operation".to_owned(), "daily".to_owned()],
		"another currency cannot be compared: fail safe"
	);

	fx.vote(owners[0], &big.id, ApprovalVote::For).await.unwrap();
	let passed = fx.vote(owners[1], &big.id, ApprovalVote::For).await.unwrap();
	assert_eq!(passed.executable_at - passed.passed_at, 24 * HOUR, "the owners' veto window is the consilium's");
	let small = fx.propose(&scope, transfer(&scope, "1000")).await;
	assert_eq!(small.level, ApprovalLevel::Scope as i32, "at the threshold is not above it");
}

#[tokio::test]
async fn a_scope_with_one_admin_escalates_and_a_platform_of_one_owner_refuses() {
	let Some(fx) = setup().await else { return };
	let (lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let admin = fx.admins(&scope, 1).await[0];
	fx.at(T0);

	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!(opened.level, ApprovalLevel::Platform as i32);
	assert_eq!(opened.escalated_by, vec!["sole_admin".to_owned()]);
	assert!(opened.voters.iter().all(|v| v.vote == ApprovalVote::Pending as i32));
	assert_eq!(
		code(fx.vote(admin, &opened.id, ApprovalVote::For).await),
		Some(Code::PermissionDenied),
		"the lone admin sees it and is not on the owners' roster"
	);
	drop(lock);

	let (_lock, _owners) = fx.owners(1).await;
	assert_eq!(
		code(fx.services.propose(as_client(transfer(&scope, "10"), &scope)).await),
		Some(Code::FailedPrecondition),
		"one owner would decide for the platform alone"
	);
}

/// The daily limit counts LIVE proposals as well as executed ones (§5.2, decided): a batch
/// opened together must not each pass under the window and then execute above it.
#[tokio::test]
async fn proposals_opened_together_cannot_split_past_the_daily_window() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);

	let mut batch = tokio::task::JoinSet::new();
	for _ in 0..8 {
		let services = fx.services.clone();
		let request = as_client(transfer(&scope, "1000"), &scope);
		batch.spawn(async move { services.propose(request).await.map(tonic::Response::into_inner) });
	}
	let mut levels = Vec::new();
	while let Some(joined) = batch.join_next().await {
		let approval = joined.expect("the task ran").expect("every proposal opens");
		levels.push((approval.level, approval.escalated_by));
	}
	let scope_level = levels.iter().filter(|(level, _)| *level == ApprovalLevel::Scope as i32).count();
	assert_eq!(scope_level, 5, "5000 USDT a day at the scope, whatever the interleaving");
	assert!(
		levels
			.iter()
			.filter(|(level, _)| *level == ApprovalLevel::Platform as i32)
			.all(|(_, by)| by == &vec!["daily".to_owned()])
	);

	fx.at(T0 + 24 * HOUR + 1);
	let next_day = fx.propose(&scope, transfer(&scope, "1000")).await;
	assert_eq!(
		(next_day.level, next_day.escalated_by),
		(ApprovalLevel::Platform as i32, vec!["daily".to_owned()]),
		"a proposal still open a day later is still live, however long ago it was opened"
	);
}

/// An executed proposal counts for 24 hours after it was EXECUTED, not after it was
/// opened: a proposal executed late is money that moved late.
#[tokio::test]
async fn an_execution_counts_against_the_window_for_a_day_after_it_happened() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let mut batch = Vec::new();
	for _ in 0..5 {
		let opened = fx.propose(&scope, transfer(&scope, "1000")).await;
		assert_eq!(opened.level, ApprovalLevel::Scope as i32);
		fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
		fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
		batch.push(opened.id);
	}
	fx.at(T0 + 25 * HOUR);
	for id in &batch {
		fx.report(&scope, id, ApprovalOutcome::Executed, "").await.unwrap();
	}
	let level_at = |at: i64| {
		fx.at(at);
		async { fx.propose(&scope, transfer(&scope, "1000")).await.level }
	};
	assert_eq!(level_at(T0 + 25 * HOUR + 1).await, ApprovalLevel::Platform as i32, "5000 executed an instant ago");
	assert_eq!(level_at(T0 + 49 * HOUR - 1).await, ApprovalLevel::Platform as i32, "still inside the day after execution");
	assert_eq!(level_at(T0 + 49 * HOUR + 1).await, ApprovalLevel::Scope as i32, "a day after execution it no longer counts");
}

#[tokio::test]
async fn one_namespace_neither_sees_nor_executes_anothers_decisions() {
	let Some(fx) = setup().await else { return };
	let mine = fx.scope().await;
	let theirs = fx.scope().await;
	let my_admins = fx.admins(&mine, 2).await;
	let their_admins = fx.admins(&theirs, 2).await;
	let outsider = fx.user("outsider").await;
	fx.at(T0);
	let opened = fx.propose(&mine, transfer(&mine, "10")).await;

	let foreign_kind = ProposeRequest {
		scope: mine.id.clone(),
		..transfer(&mine, "10")
	};
	assert_eq!(
		code(fx.services.propose(as_client(foreign_kind, &theirs)).await),
		Some(Code::PermissionDenied),
		"only a kind's namespace proposes it"
	);
	let mut into_their_scope = transfer(&mine, "10");
	into_their_scope.scope = theirs.id.clone();
	assert_eq!(
		code(fx.services.propose(as_client(into_their_scope, &mine)).await),
		Some(Code::PermissionDenied),
		"a relying party opens proposals in its own scope only"
	);

	let id = || opened.id.clone();
	assert_eq!(
		code(fx.services.get_proposal(as_client(GetProposalRequest { approval_id: id() }, &theirs)).await),
		Some(Code::NotFound)
	);
	assert_eq!(
		code(
			fx.services
				.withdraw_proposal(as_client(
					WithdrawProposalRequest {
						approval_id: id(),
						reason: String::new(),
					},
					&theirs
				))
				.await
		),
		Some(Code::NotFound)
	);
	assert_eq!(code(fx.report(&theirs, &id(), ApprovalOutcome::Void, "not ours").await), Some(Code::NotFound));

	fx.vote(my_admins[0], &id(), ApprovalVote::For).await.unwrap();
	fx.vote(my_admins[1], &id(), ApprovalVote::For).await.unwrap();
	fx.at(T0 + HOUR);
	assert!(!fx.pull(&theirs).await.contains(&id()), "another namespace's decision is never served");
	assert_eq!(fx.pull(&mine).await, vec![id()]);

	for person in [their_admins[0], outsider] {
		assert_eq!(
			code(fx.people.get_approval(as_user(person, GetApprovalRequest { approval_id: id() })).await),
			Some(Code::NotFound)
		);
		assert_eq!(code(fx.vote(person, &id(), ApprovalVote::Against).await), Some(Code::NotFound));
		let listed = fx
			.people
			.list_approvals(as_user(person, ListApprovalsRequest { limit: 100, ..Default::default() }))
			.await
			.unwrap()
			.into_inner();
		assert!(listed.approvals.iter().all(|a| a.id != id()));
	}
	let listed = fx
		.people
		.list_approvals(as_user(
			my_admins[0],
			ListApprovalsRequest {
				scope: mine.id.clone(),
				state: ApprovalState::Passed as i32,
				..Default::default()
			},
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(listed.approvals.iter().map(|a| a.id.clone()).collect::<Vec<_>>(), vec![id()]);
	assert_eq!(
		code(
			fx.people
				.get_scope_approval_policy(as_user(their_admins[0], GetScopeApprovalPolicyRequest { scope: mine.id.clone() }))
				.await
		),
		Some(Code::PermissionDenied)
	);
	let policy = fx
		.people
		.get_scope_approval_policy(as_user(my_admins[0], GetScopeApprovalPolicyRequest { scope: mine.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((policy.version, policy.quorum_bps, policy.delay_secs, policy.ttl_secs), (1, 5001, 3600, 259_200));
}

#[tokio::test]
async fn propose_is_idempotent_by_dedupe_key_and_reports_bind_the_payload() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);
	let request = transfer(&scope, "200.5");
	let first = fx.propose(&scope, request.clone()).await;
	assert_eq!(first.level, ApprovalLevel::Scope as i32, "kept under the escalation so the owner roster plays no part");
	let repeat = fx.propose(&scope, request.clone()).await;
	assert_eq!(repeat.id, first.id, "the same key and content answer the proposal already open");

	let changed = ProposeRequest {
		fields: vec![text("to_account", "ops"), amount("200.6", "USDT")],
		..request.clone()
	};
	assert_eq!(code(fx.services.propose(as_client(changed, &scope)).await), Some(Code::AlreadyExists));

	let preimage = format!(
		"ev-approval-v1\n{}\n{}\n{}\namount\tAMOUNT\t200.5 USDT\nto_account\tTEXT\tops\n",
		request.kind, request.scope, request.subject_ref
	);
	let expected: String = Sha256::digest(preimage.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
	assert_eq!(first.payload_hash, expected, "the hash is over the documented canonical encoding");
}

#[tokio::test]
async fn propose_refuses_what_it_cannot_render_or_decide() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);
	let invalid = [
		ProposeRequest {
			kind: scope.kind("unknown"),
			..transfer(&scope, "1")
		},
		ProposeRequest {
			subject_ref: "payment:NOT-A-UUID".into(),
			..transfer(&scope, "1")
		},
		ProposeRequest {
			reason: String::new(),
			..transfer(&scope, "1")
		},
		ProposeRequest {
			dedupe_key: String::new(),
			..transfer(&scope, "1")
		},
		ProposeRequest {
			fields: vec![text("to_account", "see https://evil.example"), amount("1", "USDT")],
			..transfer(&scope, "1")
		},
		ProposeRequest {
			fields: vec![text("to_account", "ops"), amount("1.50", "USDT")],
			..transfer(&scope, "1")
		},
		ProposeRequest {
			fields: vec![amount("1", "USDT")],
			..transfer(&scope, "1")
		},
		ProposeRequest {
			kind: scope.kind("grant"),
			fields: vec![ApprovalFieldValue {
				key: "holder".into(),
				value: Some(Value::AuthSubject("no-such-subject".into())),
			}],
			..transfer(&scope, "1")
		},
	];
	for (i, request) in invalid.into_iter().enumerate() {
		assert_eq!(code(fx.services.propose(as_client(request, &scope)).await), Some(Code::InvalidArgument), "case {i}");
	}
	let elsewhere = ProposeRequest {
		scope: "s_nowhere_at_all".into(),
		..transfer(&scope, "1")
	};
	assert_eq!(
		code(fx.services.propose(as_client(elsewhere, &scope)).await),
		Some(Code::PermissionDenied),
		"a client names no scope but its own, known or not"
	);
	let huge = ProposeRequest {
		fields: vec![text("to_account", "ops"), amount(&"9".repeat(31), "USDT")],
		..transfer(&scope, "1")
	};
	assert_eq!(code(fx.services.propose(as_client(huge, &scope)).await), Some(Code::InvalidArgument), "31 whole digits");

	sqlx::query("UPDATE tenants SET state = 'frozen' WHERE id = $1").bind(&scope.id).execute(&fx.pool).await.unwrap();
	assert_eq!(
		code(fx.services.propose(as_client(transfer(&scope, "1"), &scope)).await),
		Some(Code::FailedPrecondition),
		"nothing new opens in a frozen scope"
	);
}

#[tokio::test]
async fn a_withdrawn_or_voided_proposal_is_closed_and_a_removed_admin_has_no_say() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);

	let withdrawn = fx.propose(&scope, transfer(&scope, "10")).await;
	let closed = fx
		.services
		.withdraw_proposal(as_client(
			WithdrawProposalRequest {
				approval_id: withdrawn.id.clone(),
				reason: "The payment was cancelled".into(),
			},
			&scope,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(state(&closed), ApprovalState::Cancelled);

	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	sqlx::query("UPDATE grants SET revoked_at = 1, revoked_by = granted_by WHERE user_id = $1 AND revoked_at IS NULL")
		.bind(admins[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(
		code(fx.vote(admins[0], &opened.id, ApprovalVote::For).await),
		Some(Code::PermissionDenied),
		"a removed admin keeps a place on the frozen roster and loses the vote"
	);
	fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	let passed = fx.vote(admins[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&passed), ApprovalState::Passed);

	fx.at(T0 + HOUR);
	assert_eq!(
		code(fx.report(&scope, &opened.id, ApprovalOutcome::Void, "").await),
		Some(Code::InvalidArgument),
		"a void says why"
	);
	let void = fx.report(&scope, &opened.id, ApprovalOutcome::Void, "The account was closed").await.unwrap();
	assert_eq!((state(&void), void.void_reason.as_str()), (ApprovalState::Void, "The account was closed"));

	let kinds = fx.people.list_approval_kinds(as_user(admins[1], ListApprovalKindsRequest {})).await.unwrap().into_inner();
	assert!(kinds.kinds.iter().any(|k| k.name == scope.kind("transfer") && k.proposer == scope.id));
}

/// The roster is frozen, but a seat taken away bites at once (§5.6): an owner who lost
/// the seat after open keeps a place on the roster and no vote.
#[tokio::test]
async fn an_owner_who_lost_the_seat_cannot_vote_on_a_frozen_roster() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.at(T0);
	let holder = fx.user("holder").await;
	let opened = fx
		.propose(
			&scope,
			ProposeRequest {
				kind: scope.kind("grant"),
				fields: vec![ApprovalFieldValue {
					key: "holder".into(),
					value: Some(Value::AuthSubject(fx.auth_subject(holder).await)),
				}],
				..transfer(&scope, "1")
			},
		)
		.await;
	assert_eq!(opened.level, ApprovalLevel::Platform as i32);
	sqlx::query("UPDATE users SET role = 'investor' WHERE id = $1")
		.bind(owners[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(code(fx.vote(owners[0], &opened.id, ApprovalVote::For).await), Some(Code::PermissionDenied));
	assert_eq!(fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap().voters.len(), 3, "the roster did not move");
}

/// The money plane speaks for `bank` in every scope; a relying party only in its own.
#[tokio::test]
async fn the_bridge_proposes_in_any_scope() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);
	let kind = format!("bank:t_{}", &scope.id[2..]);
	let version = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let mut published = fx
		.catalogs
		.get_scope_catalog(as_bridge(evconcierge_contracts::concierge::v1::GetScopeCatalogRequest {}))
		.await
		.map(|r| r.into_inner().approval_kinds)
		.unwrap_or_default();
	published.retain(|k| k.name != kind);
	published.insert(
		0,
		ApprovalKindSpec {
			name: kind.clone(),
			label: "Transfer".into(),
			description: String::new(),
			level: ApprovalLevel::Scope as i32,
			fields: vec![spec("amount", ApprovalFieldType::Amount)],
			escalations: vec![],
			proposer: String::new(),
		},
	);
	published.truncate(64);
	fx.catalogs
		.publish_scope_catalog(as_bridge(PublishScopeCatalogRequest {
			version,
			approval_kinds: published,
			notification_topics: vec![],
		}))
		.await
		.expect("publish bank's catalog");
	let opened = fx
		.services
		.propose(as_bridge(ProposeRequest {
			kind,
			fields: vec![amount("10", "USDT")],
			..transfer(&scope, "10")
		}))
		.await
		.expect("the bridge opens bank's kinds in any active scope")
		.into_inner();
	assert_eq!((opened.proposer.as_str(), opened.requested_by_client.as_str()), ("bank", ""));
}

/// Containment is never slower than the grant (decided): any persisted owner stops a
/// proposal inside its veto window, scope-level ones included.
#[tokio::test]
async fn an_owner_vetoes_a_scope_decision_inside_its_delay() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!(opened.level, ApprovalLevel::Scope as i32);
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	let vetoed = fx
		.people
		.veto_approval(as_user(
			owners[0],
			VetoApprovalRequest {
				approval_id: opened.id.clone(),
				reason: "Not with this counterparty".into(),
			},
		))
		.await
		.expect("an owner off the roster vetoes")
		.into_inner();
	assert_eq!(state(&vetoed), ApprovalState::Vetoed);
	assert_eq!(vetoed.vetoed_by, fx.auth_subject(owners[0]).await);
}

/// A passed decision is executable for 72 hours after its delay; past that it lapses to
/// VOID, unexecuted, and a late report is refused (decided).
#[tokio::test]
async fn an_unexecuted_decision_lapses_after_its_execution_window() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	let deadline = T0 + HOUR + 72 * HOUR;

	fx.at(deadline - 1);
	assert_eq!(fx.pull(&scope).await, vec![opened.id.clone()]);
	fx.at(deadline);
	assert!(fx.pull(&scope).await.is_empty(), "a lapsed decision is never served");
	let read = fx
		.people
		.get_approval(as_user(admins[0], GetApprovalRequest { approval_id: opened.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((state(&read), read.decided_at), (ApprovalState::Void, deadline));
	assert_eq!(code(fx.report(&scope, &opened.id, ApprovalOutcome::Executed, "").await), Some(Code::FailedPrecondition));
	let (stored, event): (String, String) =
		sqlx::query_as("SELECT a.state, e.event FROM approvals a JOIN approval_events e ON e.approval_id = a.id WHERE a.id = $1::uuid ORDER BY e.id DESC LIMIT 1")
			.bind(&opened.id)
			.fetch_one(&fx.pool)
			.await
			.unwrap();
	assert_eq!((stored.as_str(), event.as_str()), ("void", "lapsed"), "the refused report wrote the lapse it found");
}

/// A service learns how its proposal stands, never who the deciders are: their emails
/// and cross-plane subjects are the identity plane's.
#[tokio::test]
async fn services_and_bystanders_never_read_the_deciders_addresses() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	let asker = fx.user("asker").await;
	fx.at(T0);
	let opened = fx
		.propose(
			&scope,
			ProposeRequest {
				requested_by: fx.auth_subject(asker).await,
				..transfer(&scope, "10")
			},
		)
		.await;
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	let blank = |a: &Approval| a.requested_by_email.is_empty() && a.voters.iter().all(|v| v.email.is_empty() && v.auth_subject.is_empty());
	assert!(blank(&opened), "Propose");
	let got = fx
		.services
		.get_proposal(as_client(GetProposalRequest { approval_id: opened.id.clone() }, &scope))
		.await
		.unwrap()
		.into_inner();
	assert!(blank(&got), "GetProposal");
	assert!(got.voters.iter().all(|v| v.vote == ApprovalVote::For as i32), "the votes themselves are the service's to see");
	fx.at(T0 + HOUR);
	let pulled = fx.services.pull_approved(as_client(PullApprovedRequest { limit: 0 }, &scope)).await.unwrap().into_inner();
	assert!(pulled.approvals.iter().all(blank), "PullApproved");

	let own = fx
		.people
		.get_approval(as_user(asker, GetApprovalRequest { approval_id: opened.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert!(own.voters.iter().all(|v| v.email.is_empty()), "the asker sees their proposal, not the deciders' addresses");
	let admin_view = fx
		.people
		.get_approval(as_user(admins[0], GetApprovalRequest { approval_id: opened.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert!(admin_view.voters.iter().all(|v| !v.email.is_empty()));
}

#[tokio::test]
async fn awaiting_my_vote_forgets_a_member_who_lost_the_seat() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	assert!(fx.awaiting(admins[0], &opened.id).await);
	sqlx::query("UPDATE grants SET revoked_at = 1, revoked_by = granted_by WHERE user_id = $1 AND revoked_at IS NULL")
		.bind(admins[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert!(!fx.awaiting(admins[0], &opened.id).await, "a vote they would be refused is not asked of them");
}

#[tokio::test]
async fn a_namespace_holds_a_bounded_number_of_live_proposals() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);
	let mut first = None;
	for _ in 0..200 {
		let opened = fx.propose(&scope, transfer(&scope, "0.01")).await;
		first.get_or_insert(opened.id);
	}
	assert_eq!(code(fx.services.propose(as_client(transfer(&scope, "0.01"), &scope)).await), Some(Code::ResourceExhausted));
	fx.services
		.withdraw_proposal(as_client(
			WithdrawProposalRequest {
				approval_id: first.unwrap(),
				reason: String::new(),
			},
			&scope,
		))
		.await
		.unwrap();
	fx.propose(&scope, transfer(&scope, "0.01")).await;
}
