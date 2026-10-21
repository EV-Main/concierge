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
	authz::BreakGlass,
	infrastructure::{approvals::PgApprovals, db, relying_parties::PgRelyingParties, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	ports::{ApprovalRepository, RelyingPartyRepository, UserDirectoryRepository},
	scope_catalog::ScopeCatalogs,
	service_caller::ServiceCallers,
};
use domain::{authz::Role, users::UserId};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	Approval, ApprovalAmount, ApprovalEscalation, ApprovalFieldSpec, ApprovalFieldType, ApprovalFieldValue, ApprovalKindSpec, ApprovalLevel, ApprovalOutcome, ApprovalState,
	ApprovalThreshold, ApprovalVote, CancelApprovalRequest, EscalationTest, GetApprovalRequest, GetPlatformApprovalPolicyRequest, GetProposalRequest, GetScopeApprovalPolicyRequest,
	ListApprovalKindsRequest, ListApprovalsRequest, PlatformApprovalPolicy, ProposePlatformPolicyChangeRequest, ProposeRequest, ProposeScopeAdminGrantRequest,
	ProposeScopePolicyChangeRequest, PublishScopeCatalogRequest, PullApprovedRequest, ReportOutcomeRequest, ScopeApprovalPolicy, VetoApprovalRequest, VoteApprovalRequest,
	WithdrawProposalRequest, approval_execution_service_server::ApprovalExecutionService, approval_field_value::Value, approval_service_server::ApprovalService,
	propose_scope_admin_grant_request, scope_catalog_service_server::ScopeCatalogService,
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
	tokens: Arc<FakeTokens>,
	repo: Arc<PgApprovals>,
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
	let tokens = Arc::new(FakeTokens::default());
	Some(Fx {
		people: Approvals::new(users.clone(), Arc::new(BreakGlass::new(Vec::new())), repo.clone(), catalog_repo.clone()),
		services: ApprovalExecution::new(callers.clone(), repo.clone(), catalog_repo.clone()).with_user_tokens(tokens.clone()),
		tokens,
		repo,
		catalogs: ScopeCatalogs::new(callers, catalog_repo),
		rp: PgRelyingParties::new(pool.clone()),
		users,
		pool,
		url,
		clock,
	})
}

/// This plane's verifier as the approvals see it: a token is valid when a test minted it.
/// The signature check itself is `evconcierge_auth`'s and tested there.
#[derive(Default)]
struct FakeTokens {
	issued: std::sync::Mutex<std::collections::HashMap<String, Claims>>,
}

#[async_trait::async_trait]
impl concierge::ports::UserTokenVerifier for FakeTokens {
	async fn verify(&self, token: &str) -> Result<Claims, evconcierge_auth::AuthError> {
		self.issued.lock().unwrap().get(token).cloned().ok_or(evconcierge_auth::AuthError::InvalidToken)
	}
}

impl FakeTokens {
	/// A token for `user` minted at `iat` by a re-authentication, so `auth_time` = `iat`:
	/// the token a proposer presents when the person just proved themselves again.
	fn mint(&self, user: UserId, iat: i64) -> String {
		self.mint_signed_in(user, iat, Some(iat))
	}

	/// A token for `user` minted at `iat` for a session last authenticated at `auth_time`
	/// (`None`: a session older than the claim).
	fn mint_signed_in(&self, user: UserId, iat: i64, auth_time: Option<i64>) -> String {
		let token = format!("token-{}", Uuid::new_v4());
		self.issued.lock().unwrap().insert(
			token.clone(),
			Claims {
				sub: user.to_string(),
				iss: "https://auth.concierge.ev".into(),
				aud: "concierge".into(),
				exp: u64::MAX,
				iat: u64::try_from(iat).unwrap(),
				typ: TokenType::Access,
				jti: None,
				token_version: 0,
				auth_time: auth_time.map(|at| u64::try_from(at).unwrap()),
			},
		);
		token
	}
}

fn with_user_token<T>(mut request: Request<T>, token: &str) -> Request<T> {
	request.metadata_mut().insert("x-ev-user-token", MetadataValue::try_from(token).unwrap());
	request
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
		auth_time: None,
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
	let read = fx.get(owners[1], &opened.id).await;
	assert_eq!(state(&read), ApprovalState::Void, "a change of the owners voids every live platform decision (D24)");
	assert!(read.void_reason.contains("owners changed"), "{}", read.void_reason);
	assert_eq!(code(fx.vote(owners[1], &opened.id, ApprovalVote::For).await), Some(Code::FailedPrecondition));
	let event: String = sqlx::query_scalar("SELECT event FROM approval_events WHERE approval_id = $1::uuid ORDER BY id DESC LIMIT 1")
		.bind(&opened.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(event, "roster_changed", "written in the transaction that moved the seat");
}

/// The money plane speaks for `bank` in every scope; a relying party only in its own.
#[tokio::test]
async fn the_bridge_proposes_in_any_scope() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.at(T0);
	let kind = fx.bank_kind(&scope).await;
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

	fx.at(deadline - HOUR - 1);
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

// ---------------------------------------------------------------------------------
// This plane's own kinds (`concierge:*`), the executor, lost seats, execution window.
// ---------------------------------------------------------------------------------

impl Fx {
	/// One pass of the executor of this plane's own kinds, as the background loop runs it.
	/// The pass is global — it takes on every due `concierge:*` decision in the database,
	/// other suites' too — so a test asserts on its own proposals, never on the count.
	async fn execute(&self) {
		let mut backoff = concierge::approvals::ExecutorBackoff::default();
		concierge::approvals::execute_due(self.repo.as_ref(), &mut backoff, std::time::Duration::from_secs(30))
			.await
			.expect("an executor pass");
	}

	async fn get(&self, who: UserId, id: &str) -> Approval {
		self.people
			.get_approval(as_user(who, GetApprovalRequest { approval_id: id.into() }))
			.await
			.expect("get")
			.into_inner()
	}

	async fn grant_admin(&self, who: UserId, scope: &Scope, subject: UserId) -> Result<Approval, tonic::Status> {
		self.people
			.propose_scope_admin_grant(as_user(
				who,
				ProposeScopeAdminGrantRequest {
					scope: scope.id.clone(),
					subject: Some(propose_scope_admin_grant_request::Subject::UserId(subject.to_string())),
					reason: "Runs the desk from Monday".into(),
				},
			))
			.await
			.map(tonic::Response::into_inner)
	}

	async fn change_policy(&self, who: UserId, policy: ScopeApprovalPolicy) -> Result<Approval, tonic::Status> {
		self.people
			.propose_scope_policy_change(as_user(
				who,
				ProposeScopePolicyChangeRequest {
					policy: Some(policy),
					reason: "Tighter limits for the quarter".into(),
				},
			))
			.await
			.map(tonic::Response::into_inner)
	}

	async fn holds_admin(&self, scope: &Scope, user: UserId) -> bool {
		sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grants WHERE user_id = $1 AND target = $2 || ':admin' AND revoked_at IS NULL)")
			.bind(user.raw())
			.bind(&scope.id)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	/// A `bank:` kind of the money plane's catalog, published for this test.
	/// Add `kind` to the money plane's catalog. Every suite in this binary shares that one
	/// catalog and republishes it whole, so publications are serialised and versioned past
	/// the stored one, or two tests would each publish a catalog missing the other's kind.
	async fn publish_bank_kind(&self, kind: ApprovalKindSpec) {
		self.publish_bank(kind).await.expect("publish bank's catalog");
	}

	/// The money plane's in-scope transfer, as every suite here publishes it: one spec, so
	/// suites sharing the catalog never publish it two ways.
	async fn bank_kind(&self, _scope: &Scope) -> String {
		let kind = "bank:account_transfer".to_owned();
		self.publish_bank_kind(ApprovalKindSpec {
			name: kind.clone(),
			label: "Transfer".into(),
			description: String::new(),
			level: ApprovalLevel::Scope as i32,
			fields: vec![spec("amount", ApprovalFieldType::Amount)],
			escalations: vec![],
			proposer: String::new(),
		})
		.await;
		kind
	}
}

fn policy(scope: &Scope, delay_secs: u32, thresholds: Vec<ApprovalThreshold>) -> ScopeApprovalPolicy {
	ScopeApprovalPolicy {
		scope: scope.id.clone(),
		version: 0,
		quorum_bps: 10_000,
		delay_secs,
		ttl_secs: 86_400,
		thresholds,
	}
}

fn per_operation(scope: &Scope, value: &str) -> ApprovalThreshold {
	ApprovalThreshold {
		kind: scope.kind("transfer"),
		parameter: "per_operation".into(),
		value: value.into(),
	}
}

#[tokio::test]
async fn this_planes_own_kinds_are_listed_beside_the_published_ones() {
	let Some(fx) = setup().await else { return };
	let anyone = fx.user("anyone").await;
	let kinds = fx.people.list_approval_kinds(as_user(anyone, ListApprovalKindsRequest {})).await.unwrap().into_inner().kinds;
	for name in ["concierge:scope_admin_grant", "concierge:scope_policy_change"] {
		let kind = kinds.iter().find(|k| k.name == name).unwrap_or_else(|| panic!("{name} is listed"));
		assert_eq!((kind.proposer.as_str(), kind.level), ("concierge", ApprovalLevel::Platform as i32));
	}
}

/// D23: the opener of a `concierge:*` proposal is proven by the session, so they do not
/// vote on what they asked for.
#[tokio::test]
async fn the_owners_grant_a_scope_admin_and_the_opener_does_not_vote() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let subject = fx.user("subject").await;
	fx.at(T0);

	let opened = fx.grant_admin(owners[0], &scope, subject).await.expect("an owner opens it");
	assert_eq!((opened.kind.as_str(), opened.proposer.as_str()), ("concierge:scope_admin_grant", "concierge"));
	assert_eq!(opened.level, ApprovalLevel::Platform as i32);
	assert_eq!(opened.requested_by, fx.auth_subject(owners[0]).await);
	assert_eq!((opened.voters.len(), opened.threshold), (2, 2), "the two other owners decide");
	assert_eq!(code(fx.vote(owners[0], &opened.id, ApprovalVote::For).await), Some(Code::PermissionDenied));
	assert_eq!(
		code(fx.grant_admin(owners[1], &scope, subject).await),
		Some(Code::AlreadyExists),
		"one grant of one person in one scope is decided once at a time"
	);

	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	let passed = fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&passed), ApprovalState::Passed);
	fx.execute().await;
	assert!(!fx.holds_admin(&scope, subject).await);

	fx.at(T0 + 24 * HOUR);
	fx.execute().await;
	fx.execute().await;
	assert_eq!(state(&fx.get(owners[1], &opened.id).await), ApprovalState::Executed);
	assert!(fx.holds_admin(&scope, subject).await);
	let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM grants WHERE user_id = $1 AND target = $2 || ':admin'")
		.bind(subject.raw())
		.bind(&scope.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(grants, 1, "one decision, one execution");
	let granted_by: Uuid = sqlx::query_scalar("SELECT granted_by FROM grants WHERE user_id = $1 AND target = $2 || ':admin' AND revoked_at IS NULL")
		.bind(subject.raw())
		.bind(&scope.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(granted_by, owners[0].raw(), "the grant names who asked for it");

	let next = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!(next.escalated_by, vec!["sole_admin".to_owned()], "the new admin is on the scope roster, alone so far");
}

#[tokio::test]
async fn who_may_open_a_scope_admin_grant() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let seat = fx.user("seat").await;
	fx.users.set_role(seat, Role::Admin).await.unwrap();
	let investor = fx.user("investor").await;
	let subject = fx.user("subject").await;
	fx.at(T0);

	assert_eq!(code(fx.grant_admin(investor, &scope, subject).await), Some(Code::PermissionDenied), "no granting seat");
	assert_eq!(code(fx.grant_admin(seat, &scope, seat).await), Some(Code::PermissionDenied), "nobody proposes themselves");
	let opened = fx.grant_admin(seat, &scope, subject).await.expect("an admin seat opens it");
	assert_eq!(opened.voters.len(), 2, "an admin seat is not an owner: the whole roster decides");

	let already = fx.admins(&scope, 1).await[0];
	assert_eq!(code(fx.grant_admin(seat, &scope, already).await), Some(Code::FailedPrecondition), "already an admin");
	let root = Scope { id: "main".into(), ..scope.clone() };
	assert_eq!(code(fx.grant_admin(seat, &root, subject).await), Some(Code::InvalidArgument), "main has no admins");
}

#[tokio::test]
async fn only_the_opener_cancels_a_concierge_proposal() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	let subject = fx.user("subject").await;
	fx.at(T0);
	let opened = fx.grant_admin(owners[0], &scope, subject).await.unwrap();
	let cancel = |who: UserId, id: String| fx.people.cancel_approval(as_user(who, CancelApprovalRequest { approval_id: id }));
	assert_eq!(code(cancel(owners[1], opened.id.clone()).await), Some(Code::PermissionDenied));
	let cancelled = cancel(owners[0], opened.id.clone()).await.unwrap().into_inner();
	assert_eq!(state(&cancelled), ApprovalState::Cancelled);

	let service = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!(
		code(cancel(admins[0], service.id.clone()).await),
		Some(Code::PermissionDenied),
		"a service's proposal is withdrawn by its proposer or vetoed"
	);
}

#[tokio::test]
async fn a_scope_policy_is_changed_by_the_owners_and_then_measures_its_proposals() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);

	assert_eq!(
		code(fx.change_policy(admins[0], policy(&scope, 1800, vec![])).await),
		Some(Code::InvalidArgument),
		"a scope's delay is at least an hour"
	);
	let unknown = ApprovalThreshold {
		kind: scope.kind("nothing"),
		..per_operation(&scope, "500")
	};
	assert_eq!(code(fx.change_policy(admins[0], policy(&scope, 7200, vec![unknown])).await), Some(Code::InvalidArgument));
	assert_eq!(
		code(fx.change_policy(fx.user("stranger").await, policy(&scope, 7200, vec![])).await),
		Some(Code::PermissionDenied),
		"a scope's admins or a granting seat"
	);

	let opened = fx
		.change_policy(admins[0], policy(&scope, 7200, vec![per_operation(&scope, "500")]))
		.await
		.expect("an admin of the scope opens it");
	assert_eq!(opened.level, ApprovalLevel::Platform as i32, "a scope never lowers its own bar");
	assert_eq!(opened.voters.len(), 3, "the opener is no owner: every owner decides");
	assert_eq!(
		code(fx.change_policy(admins[1], policy(&scope, 3600, vec![])).await),
		Some(Code::AlreadyExists),
		"one policy change per scope at a time"
	);
	fx.vote(owners[0], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	fx.at(T0 + 24 * HOUR);
	fx.execute().await;
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Executed);

	let stored = fx
		.people
		.get_scope_approval_policy(as_user(admins[0], GetScopeApprovalPolicyRequest { scope: scope.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((stored.version, stored.quorum_bps, stored.delay_secs, stored.ttl_secs), (2, 10_000, 7200, 86_400));
	assert_eq!(stored.thresholds.len(), 1);

	let over = fx.propose(&scope, transfer(&scope, "600")).await;
	assert_eq!(over.escalated_by, vec!["per_operation".to_owned()], "the new threshold binds");
	let under = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!((under.level, under.threshold, under.policy_version), (ApprovalLevel::Scope as i32, 2, 2));
	assert_eq!(under.expires_at, T0 + 24 * HOUR + 86_400);
	fx.vote(admins[0], &under.id, ApprovalVote::For).await.unwrap();
	let passed = fx.vote(admins[1], &under.id, ApprovalVote::For).await.unwrap();
	assert_eq!(passed.executable_at - passed.passed_at, 7200);
}

#[tokio::test]
async fn a_policy_is_checked_again_when_it_is_executed() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let opened = fx.change_policy(admins[0], policy(&scope, 7200, vec![per_operation(&scope, "500")])).await.unwrap();
	fx.vote(owners[0], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();

	fx.catalogs
		.publish_scope_catalog(as_client(
			PublishScopeCatalogRequest {
				version: 200,
				approval_kinds: vec![],
				notification_topics: vec![],
			},
			&scope,
		))
		.await
		.expect("the scope withdraws its kinds");
	fx.at(T0 + 24 * HOUR);
	fx.execute().await;
	let read = fx.get(owners[0], &opened.id).await;
	assert_eq!(state(&read), ApprovalState::Void);
	assert!(read.void_reason.contains("per_operation"), "{}", read.void_reason);
	let stored = fx
		.people
		.get_scope_approval_policy(as_user(admins[0], GetScopeApprovalPolicyRequest { scope: scope.id.clone() }))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(stored.version, 1, "nothing was installed");
}

/// A vote is the seat's, not the person's: an admin removed after voting FOR no longer
/// carries the proposal (decided).
#[tokio::test]
async fn a_for_vote_of_someone_who_lost_the_seat_is_not_counted() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	sqlx::query("UPDATE grants SET revoked_at = 1, revoked_by = granted_by WHERE user_id = $1 AND revoked_at IS NULL")
		.bind(admins[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	let one = fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&one), ApprovalState::Open, "the removed admin's FOR does not make two");
	let two = fx.vote(admins[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&two), ApprovalState::Passed);
}

/// A proposer is served a decision until an hour before it lapses, so whatever it pulls it
/// still has time to report (review of #139).
#[tokio::test]
async fn pulling_stops_an_hour_before_the_lapse() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	let passed = fx.vote(admins[1], &opened.id, ApprovalVote::For).await.unwrap();
	let lapse = passed.executable_at + 72 * HOUR;
	assert_eq!(passed.execute_by, lapse);

	fx.at(lapse - HOUR - 1);
	assert_eq!(fx.pull(&scope).await, vec![opened.id.clone()]);
	fx.at(lapse - HOUR);
	assert!(fx.pull(&scope).await.is_empty());
	fx.at(lapse - 1);
	let executed = fx.report(&scope, &opened.id, ApprovalOutcome::Executed, "").await.expect("a pulled decision is still reportable");
	assert_eq!(state(&executed), ApprovalState::Executed);
}

/// The live cap is per proposer AND scope: a namespace busy in one scope still opens in
/// another (review of #139).
#[tokio::test]
async fn the_live_cap_counts_one_scope() {
	let Some(fx) = setup().await else { return };
	let busy = fx.scope().await;
	let quiet = fx.scope().await;
	fx.admins(&busy, 2).await;
	fx.admins(&quiet, 2).await;
	let kind = fx.bank_kind(&busy).await;
	fx.at(T0);
	let request = |scope: &Scope| {
		as_bridge(ProposeRequest {
			kind: kind.clone(),
			scope: scope.id.clone(),
			fields: vec![amount("0.01", "USDT")],
			..transfer(scope, "0.01")
		})
	};
	for _ in 0..200 {
		fx.services.propose(request(&busy)).await.expect("under the cap");
	}
	assert_eq!(code(fx.services.propose(request(&busy)).await), Some(Code::ResourceExhausted));
	fx.services.propose(request(&quiet)).await.expect("another scope has its own cap");
}

// ---------------------------------------------------------------------------------
// Review of #140: what the owners see of a policy, verified subjects, suspended owners,
// a resilient executor, a vote that can no longer be won.
// ---------------------------------------------------------------------------------

/// The owners approve the thresholds themselves, not a count of them: the proposed policy
/// is on the proposal, and its values are in the fields `payload_hash` is taken over.
#[tokio::test]
async fn the_owners_read_the_policy_they_are_asked_to_install() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	let opened = fx.change_policy(admins[0], policy(&scope, 7200, vec![per_operation(&scope, "500")])).await.unwrap();
	let read = fx.get(owners[0], &opened.id).await;
	let proposed = read.proposed_policy.expect("the policy is on the proposal");
	assert_eq!((proposed.scope.as_str(), proposed.quorum_bps, proposed.delay_secs), (scope.id.as_str(), 10_000, 7200));
	assert_eq!(proposed.thresholds.len(), 1);
	assert_eq!(proposed.thresholds[0].value, "500");
	let threshold = read.fields.iter().find(|f| f.key == "threshold").expect("each override is a field");
	assert_eq!(threshold.value, Some(Value::Text(format!("{}/per_operation=500", scope.kind("transfer")))));
}

/// Until this plane holds its own floor on the known money kinds, a scope's policy may only
/// make its escalations stricter than the kind's own defaults (decided).
#[tokio::test]
async fn a_policy_only_tightens_the_kinds_thresholds() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	fx.at(T0);
	assert_eq!(
		code(fx.change_policy(admins[0], policy(&scope, 7200, vec![per_operation(&scope, "1000.5")])).await),
		Some(Code::InvalidArgument),
		"1000 is the kind's own default"
	);
}

#[tokio::test]
async fn a_scope_admin_is_an_account_with_a_proven_address() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let unproven = fx.users.resolve(common::google("unproven", false), 0).await.unwrap().id();
	fx.at(T0);
	assert_eq!(code(fx.grant_admin(owners[0], &scope, unproven).await), Some(Code::FailedPrecondition));

	let subject = fx.user("subject").await;
	let opened = fx.grant_admin(owners[0], &scope, subject).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	sqlx::query("UPDATE users SET email_verified = FALSE WHERE id = $1")
		.bind(subject.raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	fx.at(T0 + 24 * HOUR);
	fx.execute().await;
	let read = fx.get(owners[1], &opened.id).await;
	assert_eq!(state(&read), ApprovalState::Void);
	assert!(read.void_reason.contains("not verified"), "{}", read.void_reason);
	assert!(!fx.holds_admin(&scope, subject).await);
}

/// A temporary hold is one operator's brake, not a change of the owners (D24(2), owner's
/// decision): the held owner has no say while held, and nothing is voided or paused.
#[tokio::test]
async fn a_hold_on_an_owner_is_not_a_change_of_the_owners() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.at(T0);
	let opened = fx.grant_admin(owners[0], &scope, fx.user("subject").await).await.unwrap();
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	let changed = fx.platform_policy(owners[0]).await.roster_changed_at;

	let action = concierge::infrastructure::users::AdminAction {
		actor: Some(owners[2]),
		action: "held",
		reason: "credential stuffing".into(),
		..Default::default()
	};
	fx.users.hold_user(owners[1], &action, owners[2], fx.db_now().await).await.expect("an owner holds an owner");
	assert_eq!(state(&fx.get(owners[2], &opened.id).await), ApprovalState::Open, "a hold voids nothing");
	assert_eq!(fx.platform_policy(owners[0]).await.roster_changed_at, changed, "and pauses nothing");
	let other = fx.grant_admin(owners[0], &scope, fx.user("other").await).await;
	assert!(other.is_ok(), "new platform decisions still open: {other:?}");
	let still = fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_ne!(state(&still), ApprovalState::Passed, "the held owner's FOR does not carry it while held");

	let lift = concierge::infrastructure::users::AdminAction {
		actor: Some(owners[2]),
		action: "reinstated",
		..Default::default()
	};
	fx.users.reinstate_outside_governance(owners[1], &lift, fx.db_now().await).await.expect("the hold is lifted");
	assert_eq!(fx.platform_policy(owners[0]).await.roster_changed_at, changed, "lifting a hold is no change either");
}

/// An owner suspended indefinitely by the consilium's verdict, and reinstated from it, IS a
/// change of the owners: live platform decisions are void and new ones pause.
#[tokio::test]
async fn a_consilium_suspension_of_an_owner_changes_the_owners() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.at(T0);
	let opened = fx.grant_admin(owners[0], &scope, fx.user("subject").await).await.unwrap();
	let before = fx.platform_policy(owners[0]).await.roster_changed_at;

	// The columns the executed suspension verdict writes (`domain::users::User::suspend`).
	sqlx::query("UPDATE users SET status = 'disabled', suspended_by = 'governance' WHERE id = $1")
		.bind(owners[1].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Void);
	let suspended = fx.platform_policy(owners[0]).await;
	assert!(suspended.roster_changed_at >= before, "stamped by the store's clock");
	fx.at(suspended.roster_changed_at + i64::from(suspended.cooldown_secs) - 1);
	assert_eq!(
		code(fx.grant_admin(owners[0], &scope, fx.user("next").await).await),
		Some(Code::FailedPrecondition),
		"platform decisions pause"
	);

	sqlx::query("UPDATE users SET status = 'active', suspended_by = NULL WHERE id = $1")
		.bind(owners[1].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	assert!(
		fx.platform_policy(owners[0]).await.roster_changed_at >= suspended.roster_changed_at,
		"reinstating from a verdict is a change too"
	);
	let changes: i64 = sqlx::query_scalar("SELECT count(*) FROM approval_events WHERE approval_id = $1::uuid AND event = 'roster_changed'")
		.bind(&opened.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(changes, 1, "voided once, by the suspension");
}

/// One decision the executor cannot carry out must not stop the ones behind it.
#[tokio::test]
async fn the_executor_carries_on_past_a_failing_decision() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let broken_scope = fx.scope().await;
	let scope = fx.scope().await;
	let admins = fx.admins(&broken_scope, 2).await;
	fx.at(T0);
	let broken = fx.change_policy(admins[0], policy(&broken_scope, 7200, vec![])).await.unwrap();
	let subject = fx.user("subject").await;
	fx.at(T0 + 1);
	let fine = fx.grant_admin(owners[0], &scope, subject).await.unwrap();
	fx.vote(owners[0], &broken.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[1], &broken.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[1], &fine.id, ApprovalVote::For).await.unwrap();
	// A row already naming the decision makes its install fail on `approval_id`'s
	// uniqueness: a failure of the store, not a refusal of the decision.
	sqlx::query(
		"INSERT INTO scope_approval_policies (scope, version, quorum_bps, delay_secs, ttl_secs, thresholds, approval_id, installed_at) \
		 VALUES ($1, 2, 5001, 3600, 3600, '[]', $2::uuid, 0)",
	)
	.bind(&broken_scope.id)
	.bind(&broken.id)
	.execute(&fx.pool)
	.await
	.unwrap();
	fx.at(T0 + 25 * HOUR);
	fx.execute().await;
	assert_eq!(state(&fx.get(owners[0], &fine.id).await), ApprovalState::Executed);
	assert_eq!(state(&fx.get(owners[0], &broken.id).await), ApprovalState::Passed, "left for the next pass");
}

/// A proposal is REJECTED only by the AGAINST votes of seated members — more of them than
/// the roster could spare. A seat lost does not reject anything: what can no longer be
/// carried for want of seats is left to expire (review of #140).
#[tokio::test]
async fn only_seated_against_votes_reject() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	fx.at(T0);
	let opened = fx.propose(&scope, transfer(&scope, "10")).await;
	fx.vote(admins[0], &opened.id, ApprovalVote::For).await.unwrap();
	sqlx::query("UPDATE grants SET revoked_at = 1, revoked_by = granted_by WHERE user_id = $1 AND revoked_at IS NULL")
		.bind(admins[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	let against = fx.vote(admins[1], &opened.id, ApprovalVote::Against).await.unwrap();
	assert_eq!(state(&against), ApprovalState::Open, "one seated AGAINST of three is not more than the one the roster can spare");
	let last = fx.vote(admins[2], &opened.id, ApprovalVote::For).await.unwrap();
	assert_eq!(state(&last), ApprovalState::Open, "the removed admin's FOR still does not count; it waits out its lifetime");

	let second = fx.propose(&scope, transfer(&scope, "10")).await;
	assert_eq!((second.voters.len(), second.threshold), (2, 2), "the two admins left");
	let rejected = fx.vote(admins[1], &second.id, ApprovalVote::Against).await.unwrap();
	assert_eq!(state(&rejected), ApprovalState::Rejected, "two of two are needed: one seated AGAINST is one too many");
}

// ---------------------------------------------------------------------------------
// D24: a proven initiator of a money decision, and the pause after the owners change.
// ---------------------------------------------------------------------------------

impl Fx {
	/// A platform-level `bank:` kind, published beside the money plane's others.
	async fn bank_platform_kind(&self, _scope: &Scope) -> String {
		let kind = "bank:payment".to_owned();
		self.publish_bank_kind(ApprovalKindSpec {
			name: kind.clone(),
			label: "Transfer".into(),
			description: String::new(),
			level: ApprovalLevel::Platform as i32,
			fields: vec![spec("amount", ApprovalFieldType::Amount)],
			escalations: vec![],
			proposer: String::new(),
		})
		.await;
		kind
	}

	async fn payment(&self, kind: &str, scope: &Scope, asker: Option<UserId>, token: Option<&str>) -> Result<Approval, tonic::Status> {
		let requested_by = match asker {
			Some(user) => self.auth_subject(user).await,
			None => String::new(),
		};
		let request = as_bridge(ProposeRequest {
			kind: kind.into(),
			requested_by,
			fields: vec![amount("10", "USDT")],
			..transfer(scope, "10")
		});
		let request = match token {
			Some(token) => with_user_token(request, token),
			None => request,
		};
		self.services.propose(request).await.map(tonic::Response::into_inner)
	}

	async fn db_now(&self) -> i64 {
		sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn platform_policy(&self, owner: UserId) -> PlatformApprovalPolicy {
		self.people
			.get_platform_approval_policy(as_user(owner, GetPlatformApprovalPolicyRequest {}))
			.await
			.expect("an owner reads it")
			.into_inner()
	}
}

/// D24(1): the person who asked for a money decision does not decide it — when the
/// proposer proves who that was with their own access token. A name alone proves nothing
/// and changes nothing.
#[tokio::test]
async fn a_proven_initiator_does_not_vote_on_a_money_decision() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let kind = fx.bank_platform_kind(&scope).await;
	fx.at(T0);

	let named = fx.payment(&kind, &scope, Some(owners[0]), None).await.unwrap();
	assert_eq!(named.voters.len(), 3, "a name without a token is information");
	fx.services
		.withdraw_proposal(as_bridge(WithdrawProposalRequest {
			approval_id: named.id.clone(),
			reason: String::new(),
		}))
		.await
		.unwrap();

	assert!(!named.requested_by_proven);
	let token = fx.tokens.mint(owners[0], T0);
	let proven = fx.payment(&kind, &scope, Some(owners[0]), Some(&token)).await.expect("a proven initiator");
	assert_eq!((proven.voters.len(), proven.threshold), (2, 2), "the two other owners decide");
	assert!(proven.requested_by_proven, "the deciders read that the name was proven");
	let notice: i64 = sqlx::query_scalar("SELECT count(*) FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.dedupe_key = $2")
		.bind(owners[0].raw())
		.bind(format!("approval:{}", proven.id))
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(notice, 1, "the person it names hears that a decision was opened in their name");
	assert_eq!(code(fx.vote(owners[0], &proven.id, ApprovalVote::For).await), Some(Code::PermissionDenied));

	let elsewhere = fx.tokens.mint(owners[1], T0);
	assert_eq!(
		code(fx.payment(&kind, &scope, Some(owners[0]), Some(&elsewhere)).await),
		Some(Code::PermissionDenied),
		"the token is someone else's"
	);
	assert_eq!(code(fx.payment(&kind, &scope, Some(owners[0]), Some("forged")).await), Some(Code::Unauthenticated));
	fx.services
		.withdraw_proposal(as_bridge(WithdrawProposalRequest {
			approval_id: proven.id.clone(),
			reason: String::new(),
		}))
		.await
		.unwrap();
	let spent = fx.payment(&kind, &scope, Some(owners[0]), Some(&token)).await.unwrap_err();
	assert_eq!(spent.code(), Code::FailedPrecondition, "one token proves one request: {}", spent.message());
	assert!(spent.message().contains("already spent"), "{}", spent.message());
	let stale = fx.tokens.mint(owners[0], T0 - 121);
	let refused = fx.payment(&kind, &scope, Some(owners[0]), Some(&stale)).await.unwrap_err();
	assert_eq!(
		refused.code(),
		Code::FailedPrecondition,
		"a proof is a token minted for this request, not one kept from a session"
	);
	assert!(refused.message().starts_with("reauth_required: "), "{}", refused.message());
	assert_eq!(
		code(fx.payment(&kind, &scope, None, Some(&token)).await),
		Some(Code::InvalidArgument),
		"a token names no one without requested_by"
	);
}

/// concierge#171: a young token shows only that the session was alive — a refresh mints one
/// with the old `auth_time`. The proof needs the person to have re-authenticated within
/// the same 120 s, and its refusal carries a word the proposer can send them to re-auth by.
#[tokio::test]
async fn a_proof_needs_a_re_authentication_within_the_window() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let kind = fx.bank_platform_kind(&scope).await;
	fx.at(T0);
	let reauth_required = |result: Result<Approval, tonic::Status>, why: &str| {
		let refused = result.unwrap_err();
		assert_eq!(refused.code(), Code::FailedPrecondition, "{why}: {}", refused.message());
		assert!(refused.message().starts_with("reauth_required: "), "{why}: {}", refused.message());
	};

	let refreshed = fx.tokens.mint_signed_in(owners[0], T0, Some(T0 - 121));
	reauth_required(
		fx.payment(&kind, &scope, Some(owners[0]), Some(&refreshed)).await,
		"a token refreshed just now for a session signed in earlier",
	);
	let unclaimed = fx.tokens.mint_signed_in(owners[0], T0, None);
	reauth_required(fx.payment(&kind, &scope, Some(owners[0]), Some(&unclaimed)).await, "a session older than the claim");

	let edge = fx.tokens.mint_signed_in(owners[0], T0, Some(T0 - 120));
	assert!(
		fx.payment(&kind, &scope, Some(owners[0]), Some(&edge)).await.unwrap().requested_by_proven,
		"120 s after the re-authentication still proves"
	);
	let reauthenticated = fx.tokens.mint(owners[0], T0);
	let opened = fx
		.payment(&kind, &scope, Some(owners[0]), Some(&reauthenticated))
		.await
		.expect("a token from a re-authentication proves who asked");
	assert!(opened.requested_by_proven);
	assert_eq!(opened.voters.len(), 2, "the initiator is off the roster");
	let spent = fx.payment(&kind, &scope, Some(owners[0]), Some(&reauthenticated)).await.unwrap_err();
	assert_eq!(spent.code(), Code::FailedPrecondition, "{}", spent.message());
	assert!(spent.message().contains("already spent"), "one re-authenticated token proves one request: {}", spent.message());
}

/// Taking the initiator off a service's roster must not leave one owner deciding a money
/// decision alone: two others are required.
#[tokio::test]
async fn a_proven_initiator_needs_two_other_owners() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	let kind = fx.bank_platform_kind(&scope).await;
	fx.at(T0);
	let token = fx.tokens.mint(owners[0], T0);
	let refused = fx.payment(&kind, &scope, Some(owners[0]), Some(&token)).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition);
	assert!(refused.message().contains("besides the initiator"), "{}", refused.message());
	assert!(refused.message().contains("not_enough_owners_besides_initiator"), "a code a proposer can tell from the others");
}

/// The floor of two other deciders counts owners who can decide: a held owner is on the
/// roster and has no say while held.
#[tokio::test]
async fn the_floor_counts_owners_who_can_decide() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let kind = fx.bank_platform_kind(&scope).await;
	let action = concierge::infrastructure::users::AdminAction {
		actor: Some(owners[1]),
		action: "held",
		reason: "credential stuffing".into(),
		..Default::default()
	};
	fx.users.hold_user(owners[2], &action, owners[1], fx.db_now().await).await.expect("an owner holds an owner");
	fx.at(T0);
	let token = fx.tokens.mint(owners[0], T0);
	let refused = fx.payment(&kind, &scope, Some(owners[0]), Some(&token)).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition, "one active owner besides the initiator: {}", refused.message());
	assert!(fx.payment(&kind, &scope, None, None).await.is_ok(), "two active owners decide a decision nobody proved");
}

/// The pause holds in the store too: a platform row written inside it — by a binary that
/// does not know the rule — is refused by the database.
#[tokio::test]
async fn the_store_refuses_a_platform_decision_inside_the_pause() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(2).await;
	let policy = fx.platform_policy(owners[0]).await;
	let inside = policy.roster_changed_at + i64::from(policy.cooldown_secs) - 1;
	let insert = |created_at: i64| {
		sqlx::query(
			"INSERT INTO approvals (id, kind, proposer, scope, level, subject_ref, fields, payload_hash, reason, roster_size, threshold, \
			 policy_version, delay_secs, created_at, expires_at, dedupe_key) \
			 VALUES (gen_random_uuid(), 'bank:direct', 'bank', 'main', 'platform', 'payment:' || gen_random_uuid(), '[]', repeat('0', 64), 'r', 2, 2, \
			 0, 86400, $1, $1 + 100, gen_random_uuid()::TEXT)",
		)
		.bind(created_at)
		.execute(&fx.pool)
	};
	let refused = insert(inside).await.unwrap_err();
	assert!(refused.to_string().contains("pause"), "{refused}");
	insert(inside + 1).await.expect("after the pause the row is the code's to judge");
}

/// D24(2): after the owners change, platform decisions pause for the platform policy's
/// cool-down, and the live ones were voided by the change itself.
#[tokio::test]
async fn platform_decisions_pause_after_the_owners_change() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	let kind = fx.bank_platform_kind(&scope).await;
	let policy = fx.platform_policy(owners[0]).await;
	assert!(policy.cooldown_secs > 0, "this suite never installs a zero cool-down");
	let changed = policy.roster_changed_at;
	assert!(changed > 0, "seating the owners was a change");

	fx.at(changed + i64::from(policy.cooldown_secs) - 1);
	let paused = fx.payment(&kind, &scope, None, None).await.unwrap_err();
	assert_eq!(paused.code(), Code::FailedPrecondition, "{}", paused.message());
	assert_eq!(
		fx.propose(&scope, transfer(&scope, "10")).await.level,
		ApprovalLevel::Scope as i32,
		"a scope's own decisions do not pause"
	);

	fx.at(changed + i64::from(policy.cooldown_secs));
	let live = fx.payment(&kind, &scope, None, None).await.expect("the pause is over");
	fx.users.set_role(fx.user("newcomer").await, Role::Owner).await.unwrap();
	let read = fx.get(owners[0], &live.id).await;
	assert_eq!(state(&read), ApprovalState::Void);
	let after = fx.platform_policy(owners[0]).await;
	assert!(after.roster_changed_at >= fx.db_now().await - 60, "the change is stamped by the store's clock");
}

#[tokio::test]
async fn the_owners_set_the_platform_cooldown() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	fx.at(T0);
	let propose = |who: UserId, cooldown_secs: u32| {
		fx.people.propose_platform_policy_change(as_user(
			who,
			ProposePlatformPolicyChangeRequest {
				policy: Some(PlatformApprovalPolicy {
					version: 0,
					cooldown_secs,
					roster_changed_at: 0,
				}),
				reason: "Owners rotate weekly now".into(),
			},
		))
	};
	assert_eq!(code(propose(owners[0], 15 * 24 * 3600).await), Some(Code::InvalidArgument), "at most 14 days");
	let admin = fx.user("admin").await;
	fx.users.set_role(admin, Role::Admin).await.unwrap();
	assert_eq!(code(propose(admin, 7200).await), Some(Code::PermissionDenied), "owners only");

	let before = fx.platform_policy(owners[0]).await;
	let opened = propose(owners[0], 7200).await.expect("an owner opens it").into_inner();
	assert_eq!((opened.kind.as_str(), opened.voters.len()), ("concierge:platform_policy", 2));
	assert!(opened.fields.iter().any(|f| f.key == "cooldown_secs" && f.value == Some(Value::Count(7200))));
	fx.vote(owners[1], &opened.id, ApprovalVote::For).await.unwrap();
	fx.vote(owners[2], &opened.id, ApprovalVote::For).await.unwrap();
	fx.at(T0 + 24 * HOUR);
	fx.execute().await;
	assert_eq!(state(&fx.get(owners[0], &opened.id).await), ApprovalState::Executed);
	let after = fx.platform_policy(owners[0]).await;
	assert_eq!((after.version, after.cooldown_secs), (before.version + 1, 7200));
}

/// Only someone taken OFF a platform roster is told a decision was opened in their name:
/// a proven scope admin was never on it and has no veto to cast (live run of #141).
#[tokio::test]
async fn only_an_owner_taken_off_the_roster_is_told() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let admin = fx.admins(&scope, 2).await[0];
	let kind = fx.bank_platform_kind(&scope).await;
	fx.at(T0);
	let token = fx.tokens.mint(admin, T0);
	let opened = fx.payment(&kind, &scope, Some(admin), Some(&token)).await.expect("a proven admin asks");
	assert!(opened.requested_by_proven);
	assert_eq!(opened.voters.len(), 3, "an admin was never on the owners' roster");
	let notices: i64 = sqlx::query_scalar(
		"SELECT count(*) FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id \
		 WHERE s.user_id = $1 AND n.kind = 'approval_opened_in_your_name'",
	)
	.bind(admin.raw())
	.fetch_one(&fx.pool)
	.await
	.unwrap();
	assert_eq!(notices, 0, "nothing to veto, nothing to tell");
}

/// A retry under the same `dedupe_key` that carries a token is held to what the first call
/// was: the token must be the named person's, or the answer is the same refusal.
#[tokio::test]
async fn a_retry_with_a_token_is_checked_as_the_first_call_was() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	let kind = fx.bank_platform_kind(&scope).await;
	fx.at(T0);
	let request = |token: Option<String>| {
		let request = as_bridge(ProposeRequest {
			kind: kind.clone(),
			scope: scope.id.clone(),
			subject_ref: "payment:4f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b".into(),
			requested_by: String::new(),
			reason: "Monthly rebalance".into(),
			fields: vec![amount("10", "USDT")],
			dedupe_key: format!("retry-{}", scope.id),
		});
		(request, token)
	};
	let asker = fx.auth_subject(owners[0]).await;
	let send = |token: Option<String>| {
		let (mut request, token) = request(token);
		request.get_mut().requested_by = asker.clone();
		let request = match token {
			Some(token) => with_user_token(request, &token),
			None => request,
		};
		fx.services.propose(request)
	};
	let first = send(Some(fx.tokens.mint(owners[0], T0))).await.expect("the first call").into_inner();
	let again = send(Some(fx.tokens.mint(owners[0], T0)))
		.await
		.expect("a retry with a fresh token of the same person")
		.into_inner();
	assert_eq!(again.id, first.id);
	assert_eq!(send(None).await.expect("a retry without a token").into_inner().id, first.id);
	assert_eq!(
		code(send(Some(fx.tokens.mint(owners[1], T0))).await),
		Some(Code::PermissionDenied),
		"someone else's token is refused on a retry as on the first call"
	);
	assert_eq!(code(send(Some(fx.tokens.mint(owners[0], T0 - 121))).await), Some(Code::FailedPrecondition), "and a stale one");
}

// ---------------------------------------------------------------------------------
// The floor this plane keeps on the known money kinds, whatever their catalog says (D24).
// ---------------------------------------------------------------------------------

impl Fx {
	/// Add `spec` to the money plane's catalog. Every suite in this binary shares that one
	/// catalog and republishes it whole, so publications are serialised and versioned past
	/// the stored one, or two tests would each publish a catalog missing the other's kind.
	async fn publish_bank(&self, spec: ApprovalKindSpec) -> Result<(), tonic::Status> {
		static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
		let _serial = SERIAL.lock().await;
		let stored = self
			.catalogs
			.get_scope_catalog(as_bridge(evconcierge_contracts::concierge::v1::GetScopeCatalogRequest {}))
			.await
			.map(tonic::Response::into_inner)
			.ok();
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
		let version = stored.as_ref().map_or(now, |c| c.version + 1).max(now);
		let mut kinds = stored.map(|c| c.approval_kinds).unwrap_or_default();
		kinds.retain(|k| k.name != spec.name);
		kinds.insert(0, spec);
		kinds.truncate(64);
		self.catalogs
			.publish_scope_catalog(as_bridge(PublishScopeCatalogRequest {
				version,
				approval_kinds: kinds,
				notification_topics: vec![],
			}))
			.await
			.map(drop)
	}
}

fn bank_spec(name: &str, level: ApprovalLevel, fields: Vec<ApprovalFieldSpec>, escalations: Vec<ApprovalEscalation>) -> ApprovalKindSpec {
	ApprovalKindSpec {
		name: name.into(),
		label: "Money".into(),
		description: String::new(),
		level: level as i32,
		fields,
		escalations,
		proposer: String::new(),
	}
}

#[tokio::test]
async fn a_known_money_kind_is_published_no_looser_than_the_floor() {
	let Some(fx) = setup().await else { return };
	let amount_field = || vec![spec("amount", ApprovalFieldType::Amount)];
	let refused = fx.publish_bank(bank_spec("bank:payment", ApprovalLevel::Scope, amount_field(), vec![])).await.unwrap_err();
	assert_eq!(refused.code(), Code::InvalidArgument, "a payment off the platform is the owners' always: {}", refused.message());
	let loose = ApprovalEscalation {
		parameter: "per_operation".into(),
		field_key: "amount".into(),
		test: EscalationTest::AmountAbove as i32,
		default_threshold: "2000".into(),
		currency: "USDT".into(),
	};
	assert_eq!(
		code(fx.publish_bank(bank_spec("bank:account_transfer", ApprovalLevel::Scope, amount_field(), vec![loose])).await),
		Some(Code::InvalidArgument),
		"a transfer escalates above 1000 USDT at the latest"
	);
	assert_eq!(
		code(
			fx.publish_bank(bank_spec("bank:account_transfer", ApprovalLevel::Scope, vec![spec("value", ApprovalFieldType::Amount)], vec![]))
				.await
		),
		Some(Code::InvalidArgument),
		"the floor reads the field the contract names"
	);
}

/// The floor holds even where the catalog says nothing: a transfer above 1000 USDT and a
/// payout to more than one recipient go to the owners.
#[tokio::test]
async fn the_floor_escalates_what_the_catalog_left_out() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	fx.publish_bank(bank_spec("bank:account_transfer", ApprovalLevel::Scope, vec![spec("amount", ApprovalFieldType::Amount)], vec![]))
		.await
		.expect("a transfer kind with no escalations of its own");
	fx.publish_bank(payout_spec()).await.expect("a payout kind with no escalations of its own");
	fx.at(T0);
	let propose = |kind: &str, fields: Vec<ApprovalFieldValue>| {
		fx.services.propose(as_bridge(ProposeRequest {
			kind: kind.into(),
			fields,
			..transfer(&scope, "1")
		}))
	};
	let small = propose("bank:account_transfer", vec![amount("10", "USDT")]).await.unwrap().into_inner();
	assert_eq!(small.level, ApprovalLevel::Scope as i32);
	let big = propose("bank:account_transfer", vec![amount("1000.01", "USDT")]).await.unwrap().into_inner();
	assert_eq!((big.level, big.escalated_by), (ApprovalLevel::Platform as i32, vec!["floor_per_operation".to_owned()]));

	let total = |value: &str| ApprovalFieldValue {
		key: "total".into(),
		value: Some(Value::Amount(ApprovalAmount {
			value: value.into(),
			currency: "USDT".into(),
		})),
	};
	let recipients = |n: u64| ApprovalFieldValue {
		key: "recipients".into(),
		value: Some(Value::Count(n)),
	};
	let distribution = |set: bool| ApprovalFieldValue {
		key: "distribution".into(),
		value: Some(Value::Flag(set)),
	};
	let within_budget = || ApprovalFieldValue {
		key: "over_scope_budget".into(),
		value: Some(Value::Flag(false)),
	};
	let one = propose("bank:scope_payout", vec![total("10"), recipients(1), distribution(false), within_budget()])
		.await
		.unwrap()
		.into_inner();
	assert_eq!(one.level, ApprovalLevel::Scope as i32);
	let many = propose("bank:scope_payout", vec![total("10"), recipients(2), distribution(false), within_budget()])
		.await
		.unwrap()
		.into_inner();
	assert_eq!(many.level, ApprovalLevel::Platform as i32);
	assert!(many.escalated_by.contains(&"floor_recipients".to_owned()), "{:?}", many.escalated_by);
	let split = propose("bank:scope_payout", vec![total("10"), recipients(1), distribution(false), within_budget()])
		.await
		.unwrap()
		.into_inner();
	assert_eq!(
		split.escalated_by,
		vec!["floor_daily_recipients".to_owned()],
		"a second single-recipient payout the same day is a split distribution"
	);
	let nobody = propose("bank:scope_payout", vec![total("10"), recipients(0), distribution(false), within_budget()])
		.await
		.unwrap()
		.into_inner();
	assert!(nobody.escalated_by.contains(&"floor_no_recipients".to_owned()), "{:?}", nobody.escalated_by);
	let dividend = propose("bank:scope_payout", vec![total("10"), recipients(1), distribution(true), within_budget()])
		.await
		.unwrap()
		.into_inner();
	assert!(dividend.escalated_by.contains(&"floor_distribution".to_owned()), "{:?}", dividend.escalated_by);
}

fn payout_spec() -> ApprovalKindSpec {
	bank_spec(
		"bank:scope_payout",
		ApprovalLevel::Scope,
		vec![
			spec("total", ApprovalFieldType::Amount),
			spec("recipients", ApprovalFieldType::Count),
			spec("distribution", ApprovalFieldType::Flag),
			spec("over_scope_budget", ApprovalFieldType::Flag),
		],
		vec![],
	)
}

/// A catalog may escalate on a count itself (`ESCALATION_TEST_COUNT_ABOVE`).
#[tokio::test]
async fn a_kind_escalates_on_a_count() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	let kind = scope.kind("seats");
	fx.catalogs
		.publish_scope_catalog(as_client(
			PublishScopeCatalogRequest {
				version: 300,
				approval_kinds: vec![ApprovalKindSpec {
					name: kind.clone(),
					label: "Seats".into(),
					description: String::new(),
					level: ApprovalLevel::Scope as i32,
					fields: vec![spec("seats", ApprovalFieldType::Count)],
					escalations: vec![ApprovalEscalation {
						parameter: "crowd".into(),
						field_key: "seats".into(),
						test: EscalationTest::CountAbove as i32,
						default_threshold: "3".into(),
						currency: String::new(),
					}],
					proposer: String::new(),
				}],
				notification_topics: vec![],
			},
			&scope,
		))
		.await
		.expect("a count escalation is publishable");
	fx.at(T0);
	let seats = |n: u64| {
		fx.services.propose(as_client(
			ProposeRequest {
				kind: kind.clone(),
				fields: vec![ApprovalFieldValue {
					key: "seats".into(),
					value: Some(Value::Count(n)),
				}],
				..transfer(&scope, "1")
			},
			&scope,
		))
	};
	assert_eq!(seats(3).await.unwrap().into_inner().level, ApprovalLevel::Scope as i32, "three is not above three");
	assert_eq!(seats(4).await.unwrap().into_inner().escalated_by, vec!["crowd".to_owned()]);
}

/// The person a scope admin grant names does not decide it either, when they are an owner:
/// nobody votes on their own seat (review of #140).
#[tokio::test]
async fn an_owner_named_by_a_grant_does_not_decide_it() {
	let Some(fx) = setup().await else { return };
	let (_lock, owners) = fx.owners(3).await;
	let scope = fx.scope().await;
	fx.at(T0);
	let opened = fx.grant_admin(owners[0], &scope, owners[1]).await.expect("an owner may become a scope's admin");
	let voters: Vec<String> = fx.get(owners[2], &opened.id).await.voters.into_iter().map(|v| v.auth_subject).collect();
	assert_eq!(voters, vec![fx.auth_subject(owners[2]).await], "neither the opener nor the subject");
	assert_eq!(code(fx.vote(owners[1], &opened.id, ApprovalVote::For).await), Some(Code::PermissionDenied));
}

/// The floor binds a catalog stored before it existed, or written past it: a stored
/// platform kind at scope level, and a stored escalation and scope policy above the cap,
/// still send the proposal to the owners (review of #142).
#[tokio::test]
async fn the_floor_binds_a_stored_catalog_and_policy() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let invest = Scope {
		id: "invest".into(),
		client: "invest".into(),
		secret: "invest-test-secret-invest-test-secret".into(),
	};
	fx.rp
		.set_secret_hash(&invest.client, Some(Sha256::digest(invest.secret.as_bytes()).as_slice()), 0)
		.await
		.expect("the invest client's secret");
	let catalog = serde_json::json!({
		"version": 4_000_000_000u64,
		"notification_topics": [],
		"approval_kinds": [
			{"name": "invest:holder_grant", "label": "Grant", "description": "", "level": "scope",
			 "fields": [{"key": "allocation", "label": "Allocation", "field_type": "text", "required": true, "repeated": false}],
			 "escalations": []},
			{"name": "invest:valuation_override", "label": "Mark", "description": "", "level": "scope",
			 "fields": [{"key": "deviation", "label": "Deviation", "field_type": "bps", "required": true, "repeated": false}],
			 "escalations": [{"parameter": "max_deviation", "field_key": "deviation", "test": "abs_bps_above", "default_threshold": "2000", "currency": ""}]}
		]
	});
	sqlx::query("INSERT INTO scope_catalogs (namespace, version, catalog, published_at, published_by) VALUES ('invest', $1, $2, 0, 'invest') ON CONFLICT DO NOTHING")
		.bind(4_000_000_000i64)
		.bind(&catalog)
		.execute(&fx.pool)
		.await
		.expect("store a catalog written before the floor");
	let decided: Uuid = sqlx::query_scalar(
		"INSERT INTO approvals (id, kind, proposer, scope, level, subject_ref, fields, payload_hash, reason, roster_size, threshold, \
		 policy_version, delay_secs, created_at, expires_at, dedupe_key, state, passed_at, executable_at, decided_at, outcome) \
		 VALUES (gen_random_uuid(), 'concierge:scope_policy_change', 'concierge', 'invest', 'platform', 'scope_policy:' || gen_random_uuid(), '[]', \
		 repeat('0', 64), 'r', 2, 2, 1, 86400, $1, $1 + 100, gen_random_uuid()::TEXT, 'executed', $1, $1, $1, 'executed') RETURNING id",
	)
	.bind(T0)
	.fetch_one(&fx.pool)
	.await
	.expect("an executed policy change to hang the stored policy off");
	sqlx::query(
		"INSERT INTO scope_approval_policies (scope, version, quorum_bps, delay_secs, ttl_secs, thresholds, approval_id, installed_at) \
		 SELECT 'invest', coalesce(max(version), 1) + 1, 5001, 3600, 259200, \
		 '[{\"kind\": \"invest:valuation_override\", \"parameter\": \"max_deviation\", \"value\": \"3000\"}]', $1, 0 \
		 FROM scope_approval_policies WHERE scope = 'invest'",
	)
	.bind(decided)
	.execute(&fx.pool)
	.await
	.expect("store a policy written before the floor");
	fx.at(T0);
	let propose = |kind: &str, field: ApprovalFieldValue| {
		fx.services.propose(as_client(
			ProposeRequest {
				kind: kind.into(),
				fields: vec![field],
				..transfer(&invest, "1")
			},
			&invest,
		))
	};
	let grant = propose(
		"invest:holder_grant",
		ApprovalFieldValue {
			key: "allocation".into(),
			value: Some(Value::Text("service_arb".into())),
		},
	)
	.await
	.expect("a stored holder grant opens")
	.into_inner();
	assert_eq!(grant.level, ApprovalLevel::Platform as i32, "a holder grant is the owners' whatever was stored");
	let mark = propose(
		"invest:valuation_override",
		ApprovalFieldValue {
			key: "deviation".into(),
			value: Some(Value::Bps(1500)),
		},
	)
	.await
	.expect("a mark opens")
	.into_inner();
	assert_eq!(mark.level, ApprovalLevel::Platform as i32);
	assert!(mark.escalated_by.contains(&"floor_deviation".to_owned()), "{:?}", mark.escalated_by);
}

/// The daily floor counts what is live: five transfers of 999 USDT pass at the scope, a
/// sixth the same day goes to the owners.
#[tokio::test]
async fn the_daily_floor_counts_the_live_transfers() {
	let Some(fx) = setup().await else { return };
	let (_lock, _owners) = fx.owners(2).await;
	let scope = fx.scope().await;
	fx.admins(&scope, 2).await;
	let kind = fx.bank_kind(&scope).await;
	fx.at(T0);
	let transfer_999 = || {
		fx.services.propose(as_bridge(ProposeRequest {
			kind: kind.clone(),
			fields: vec![amount("999", "USDT")],
			..transfer(&scope, "999")
		}))
	};
	for _ in 0..5 {
		assert_eq!(transfer_999().await.unwrap().into_inner().level, ApprovalLevel::Scope as i32);
	}
	let sixth = transfer_999().await.unwrap().into_inner();
	assert_eq!((sixth.level, sixth.escalated_by), (ApprovalLevel::Platform as i32, vec!["floor_daily".to_owned()]));
}

impl Fx {
	/// The approval mail queued under `prefix`, by dedupe key: (key, recipient, payload).
	async fn mails(&self, prefix: &str) -> Vec<(String, String, serde_json::Value)> {
		sqlx::query_as("SELECT dedupe_key, recipient, payload FROM notification_deliveries WHERE dedupe_key LIKE $1 || '%' ORDER BY dedupe_key")
			.bind(prefix)
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}

	async fn email(&self, user: UserId) -> String {
		sqlx::query_scalar("SELECT email FROM users WHERE id = $1").bind(user.raw()).fetch_one(&self.pool).await.unwrap()
	}

	/// Run the outcome sweep until it finds nothing: other suites' proposals share it.
	async fn sweep(&self) {
		while self.repo.mail_outcomes(500).await.expect("the outcome sweep") > 0 {}
	}
}

/// §5.5: opening a proposal queues the request to every roster member who can act on it —
/// an active account at a verified address — once, however often the proposer retries.
#[tokio::test]
async fn opening_mails_each_reachable_roster_member_once() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 2).await;
	let unproven = fx.users.resolve(common::google("unproven", false), 0).await.expect("provision").id();
	sqlx::query("INSERT INTO grants (user_id, namespace, target, granted_by, granted_at) VALUES ($1, $2, $2 || ':admin', $3, 0)")
		.bind(unproven.raw())
		.bind(&scope.id)
		.bind(admins[0].raw())
		.execute(&fx.pool)
		.await
		.unwrap();
	let requester = fx.user("requester").await;
	fx.at(T0);
	let request = ProposeRequest {
		requested_by: fx.auth_subject(requester).await,
		..transfer(&scope, "250.5")
	};
	let opened = fx.propose(&scope, request.clone()).await;
	assert_eq!(opened.voters.len(), 3, "the unproven admin is on the roster");
	fx.propose(&scope, request).await;

	let mails = fx.mails(&format!("approval_request:{}:", opened.id)).await;
	let mut expected = vec![fx.email(admins[0]).await, fx.email(admins[1]).await];
	expected.sort();
	let mut recipients: Vec<String> = mails.iter().map(|(_, to, _)| to.clone()).collect();
	recipients.sort();
	assert_eq!(recipients, expected, "each verified admin once; the unproven one never, the retry adds nothing");

	let payload = &mails[0].2;
	assert_eq!(payload["kind_label"], "Transfer between accounts", "labelled from the catalog");
	assert_eq!(payload["requested_by"], fx.email(requester).await, "the requester by address");
	assert_eq!(
		payload["fields"][1],
		serde_json::json!({"label": "amount", "value": {"type": "amount", "value": {"value": "250.5", "currency": "USDT"}}}),
		"money stays typed until it is rendered"
	);
	assert!(!payload.to_string().contains("http"), "a row stores no link: the dispatcher builds it from APPROVALS_URL");
}

/// §5.5: the requester is told each outcome once — approved, then carried out — and an
/// expiry nobody wrote is told too, by the sweep.
#[tokio::test]
async fn the_requester_is_told_each_outcome_once() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope().await;
	let admins = fx.admins(&scope, 3).await;
	let requester = fx.user("requester").await;
	let subject = fx.auth_subject(requester).await;
	fx.at(T0);
	let decided = fx
		.propose(
			&scope,
			ProposeRequest {
				requested_by: subject.clone(),
				..transfer(&scope, "250.5")
			},
		)
		.await;
	let left = fx
		.propose(
			&scope,
			ProposeRequest {
				requested_by: subject,
				..transfer(&scope, "100")
			},
		)
		.await;
	let told = |id: &str| format!("approval_outcome:{id}:");

	fx.sweep().await;
	assert!(fx.mails(&told(&decided.id)).await.is_empty(), "an open proposal is no outcome");

	fx.vote(admins[0], &decided.id, ApprovalVote::For).await.unwrap();
	fx.vote(admins[1], &decided.id, ApprovalVote::For).await.unwrap();
	fx.sweep().await;
	fx.sweep().await;
	let mails = fx.mails(&told(&decided.id)).await;
	assert_eq!(mails.len(), 1, "approved is told once, however often the sweep runs");
	assert_eq!((mails[0].1.as_str(), &mails[0].2["outcome"]), (fx.email(requester).await.as_str(), &serde_json::json!("passed")));

	fx.at(T0 + HOUR + 1);
	fx.report(&scope, &decided.id, ApprovalOutcome::Executed, "settled").await.expect("report");
	fx.sweep().await;
	let mails = fx.mails(&told(&decided.id)).await;
	let keys: Vec<&str> = mails.iter().map(|(key, _, _)| key.as_str()).collect();
	assert_eq!(keys, [format!("{}executed", told(&decided.id)), format!("{}passed", told(&decided.id))]);
	assert_eq!(mails[0].2["note"], serde_json::json!({"by": "proposer", "text": "settled"}), "the report is the proposer's words");

	fx.at(T0 + 73 * HOUR);
	fx.sweep().await;
	let mails = fx.mails(&told(&left.id)).await;
	assert_eq!(mails.len(), 1, "a lazy expiry is told without anybody touching the proposal");
	assert_eq!(mails[0].2["outcome"], "expired");
}
