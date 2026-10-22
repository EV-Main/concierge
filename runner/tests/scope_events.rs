//! The relying-party streams (`ScopeEvents.PullScopeEvents`, `UserEvents.PullUserLifecycle`
//! read by a client credential) and `ScopeCatalogService`, against a REAL Postgres
//! (`docs/SCOPES-AND-APPROVALS.md` §2, §4, §5.1, §6).
//!
//! Every test registers its own scopes (`s_<random>`) with a client and a secret, and reads
//! the streams from the head it found, so the suite shares a database with the others
//! without reading their rows as its own.

use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Arc,
};

use concierge::{
	bridge::Bridge,
	infrastructure::{
		db,
		grants::PgGrants,
		notifications::PgNotifications,
		relying_parties::PgRelyingParties,
		scope_catalogs::PgScopeCatalogs,
		scope_events::PgScopeEvents,
		users::{AdminAction, PgUsers},
	},
	notification::{InboxView, settings_of, topic_known},
	ports::{GrantActor, GrantOutcome, GrantRepository, GrantSubject, NewCode, NewSession, RelyingPartyRepository, RevokeOutcome, UserDirectoryRepository},
	scope_catalog::ScopeCatalogs,
	scope_events::ScopeEvents,
	service_caller::ServiceCallers,
};
use domain::{
	authz::Role,
	iam::{Catalog, Target},
	users::UserId,
};
use evconcierge_contracts::concierge::v1::{
	ApprovalEscalation, ApprovalFieldSpec, ApprovalFieldType, ApprovalKindSpec, ApprovalLevel, EscalationTest, GetScopeCatalogRequest, NotificationTopicSpec, PublishScopeCatalogRequest,
	PullScopeEventsRequest, PullUserLifecycleRequest, ScopeEvent, scope_catalog_service_server::ScopeCatalogService, scope_event::Kind, scope_events_server::ScopeEvents as _,
	user_events_server::UserEvents, user_lifecycle_event::Kind as LifecycleKind,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::{Code, Request, metadata::MetadataValue};
use uuid::Uuid;

mod common;

const BRIDGE_TOKEN: &str = "test-bridge-token";

struct Fx {
	pool: PgPool,
	users: Arc<PgUsers>,
	grants: PgGrants,
	rp: PgRelyingParties,
	events: ScopeEvents,
	bridge: Bridge,
	catalogs: ScopeCatalogs,
}

#[derive(Clone)]
struct Scope {
	id: String,
	client: String,
	secret: String,
}

impl Scope {
	fn p(&self, rest: &str) -> String {
		format!("{}:{rest}", self.id)
	}
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let callers = ServiceCallers::new(Some(BRIDGE_TOKEN.into()), Arc::new(PgRelyingParties::new(pool.clone())));
	Some(Fx {
		users: Arc::new(PgUsers::new(pool.clone())),
		grants: PgGrants::new(pool.clone()),
		rp: PgRelyingParties::new(pool.clone()),
		events: ScopeEvents::new(callers.clone(), Arc::new(PgScopeEvents::new(pool.clone()))),
		bridge: Bridge::new(pool.clone(), Some(BRIDGE_TOKEN.into())),
		catalogs: ScopeCatalogs::new(callers, Arc::new(PgScopeCatalogs::new(pool.clone()))),
		pool,
	})
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn as_client<T>(body: T, scope: &Scope) -> Request<T> {
	with_client(body, &scope.client, &scope.secret)
}

fn with_client<T>(body: T, client: &str, secret: &str) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("x-ev-client-id", MetadataValue::try_from(client).unwrap());
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {secret}")).unwrap());
	request
}

fn as_bridge<T>(body: T) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {BRIDGE_TOKEN}")).unwrap());
	request
}

impl Fx {
	/// A scope with one client, its secret set, and a catalog where `admin` holds all three
	/// permissions and `operator` the two lead ones.
	async fn scope(&self, observers: &[&Scope], hold_all: bool) -> Scope {
		let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
		let scope = Scope {
			id: format!("s_{tag}"),
			client: format!("c_{tag}"),
			secret: format!("{tag}{tag}{tag}"),
		};
		let observers: Vec<String> = observers.iter().map(|s| s.client.clone()).collect();
		sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, observers) VALUES ($1, $1, $2, 0, $3)")
			.bind(&scope.id)
			.bind(hold_all)
			.bind(&observers)
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
		self.publish(&scope, 1, &["work:leads:read", "work:leads:edit"]).await;
		scope
	}

	/// Publish the tenant catalog with `operator` meaning `operator`.
	async fn publish(&self, scope: &Scope, version: u64, operator: &[&str]) {
		let all = ["work:leads:read", "work:leads:edit", "admin:sources:manage"];
		let set = |names: &[&str]| names.iter().map(|n| scope.p(n)).collect::<BTreeSet<_>>();
		let catalog = Catalog {
			version,
			permissions: set(&all),
			aliases: BTreeMap::from([(scope.p("operator"), set(operator)), (scope.p("admin"), set(&all))]),
			delegations: BTreeMap::new(),
		};
		self.grants.publish(&scope.id, &scope.client, &catalog, now()).await.expect("publish the tenant catalog");
	}

	async fn user(&self, tag: &str) -> UserId {
		let unique = Uuid::new_v4();
		let email = format!("{tag}-{}@scope.example.com", &unique.simple().to_string()[..12]);
		self.users.resolve(common::google_as(&format!("scope-{tag}-{unique}"), &email, true), 0).await.unwrap().id()
	}

	async fn seat(&self) -> UserId {
		let id = self.user("seat").await;
		self.users.set_role(id, Role::Admin).await.unwrap();
		id
	}

	async fn grant(&self, actor: UserId, user: UserId, target: &str) -> GrantOutcome {
		self.grants
			.grant(
				&GrantSubject::Id(user),
				&Target::parse(target).unwrap(),
				&actor_of(actor),
				&AdminAction::system("permission_granted"),
				now(),
			)
			.await
			.expect("grant")
	}

	async fn revoke(&self, actor: UserId, user: UserId, target: &str) -> RevokeOutcome {
		self.grants
			.revoke(
				&GrantSubject::Id(user),
				&Target::parse(target).unwrap(),
				&actor_of(actor),
				&AdminAction::system("permission_revoked"),
				now(),
			)
			.await
			.expect("revoke")
	}

	/// A relying-party sign-in, as `ExchangeCode` stores it: a code, then the session it
	/// opens.
	async fn sign_in(&self, scope: &Scope, user: UserId) -> bool {
		let code_hash: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
		let t = now();
		self.rp
			.issue_code(NewCode {
				code_hash: &code_hash,
				client_id: &scope.client,
				redirect_uri: "https://x.test/cb",
				code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				user,
				token_version: 0,
				upstream_family: "family",
				issued_at: t,
				expires_at: t + 60,
				client_ip: "",
				user_agent: "",
			})
			.await
			.expect("issue a code");
		self.rp
			.open_session(NewSession {
				id: Uuid::new_v4(),
				client_id: &scope.client,
				user,
				code_hash: &code_hash,
				secret_hash: &[7u8; 32],
				token_version: 0,
				now: t,
				expires_at: t + 600,
				absolute_expires_at: t + 6000,
			})
			.await
			.expect("open the session")
	}

	async fn scope_head(&self) -> i64 {
		sqlx::query_scalar("SELECT COALESCE(max(position), 0) FROM scope_outbox").fetch_one(&self.pool).await.unwrap()
	}

	async fn lifecycle_head(&self) -> i64 {
		sqlx::query_scalar("SELECT COALESCE(max(position), 0) FROM user_outbox").fetch_one(&self.pool).await.unwrap()
	}

	/// Every scope event `request` sees past `after`, following the cursor to the head.
	async fn pull_all(&self, after: i64, auth: impl Fn(PullScopeEventsRequest) -> Request<PullScopeEventsRequest>) -> Vec<ScopeEvent> {
		let mut cursor = after;
		let mut seen = Vec::new();
		loop {
			let page = self
				.events
				.pull_scope_events(auth(PullScopeEventsRequest { after_position: cursor, limit: 500 }))
				.await
				.expect("pull")
				.into_inner();
			seen.extend(page.events);
			if page.next_position == cursor {
				return seen;
			}
			cursor = page.next_position;
		}
	}
}

fn refused<T>(result: Result<T, tonic::Status>) -> Code {
	result.map(drop).expect_err("refused").code()
}

fn code<T>(result: Result<T, tonic::Status>) -> Option<Code> {
	result.err().map(|s| s.code())
}

fn actor_of(id: UserId) -> GrantActor {
	GrantActor {
		id,
		role: Role::Admin,
		elevated: false,
	}
}

fn of_user(events: &[ScopeEvent], user: UserId) -> Vec<&ScopeEvent> {
	events.iter().filter(|e| e.user_id == user.to_string()).collect()
}

fn kinds(events: &[&ScopeEvent]) -> Vec<Kind> {
	events.iter().map(|e| e.kind()).collect()
}

#[tokio::test]
async fn a_client_sees_its_scope_and_the_scopes_that_name_it_an_observer_and_nothing_else() {
	let Some(fx) = setup().await else { return };
	let start = fx.scope_head().await;
	let a = fx.scope(&[], false).await;
	let b = fx.scope(&[&a], false).await;
	let c = fx.scope(&[], false).await;
	let seat = fx.seat().await;
	let (in_a, in_b, in_c) = (fx.user("a").await, fx.user("b").await, fx.user("c").await);
	fx.grant(seat, in_a, &a.p("operator")).await;
	fx.grant(seat, in_b, &b.p("operator")).await;
	fx.grant(seat, in_c, &c.p("operator")).await;

	let scopes_of = |events: &[ScopeEvent]| events.iter().map(|e| e.scope.clone()).collect::<BTreeSet<_>>();
	let as_a = fx.pull_all(start, |r| as_client(r, &a)).await;
	assert_eq!(scopes_of(&as_a), BTreeSet::from([a.id.clone(), b.id.clone()]), "its own scope and the one it observes");
	assert!(
		as_a.iter()
			.any(|e| e.kind() == Kind::ScopeChanged && e.scope == b.id && e.scope_snapshot.as_ref().unwrap().observers == vec![a.client.clone()])
	);
	assert_eq!(kinds(&of_user(&as_a, in_b)), [Kind::MemberJoined, Kind::GrantsChanged]);
	assert!(of_user(&as_a, in_c).is_empty(), "a scope it does not observe is invisible");

	let as_c = fx.pull_all(start, |r| as_client(r, &c)).await;
	assert_eq!(scopes_of(&as_c), BTreeSet::from([c.id.clone()]), "observing is one-way: b names a, not c");

	let as_bank = fx.pull_all(start, as_bridge).await;
	assert!(
		scopes_of(&as_bank).is_superset(&BTreeSet::from([a.id.clone(), b.id.clone(), c.id.clone()])),
		"the bridge token reads every scope"
	);

	// The lifecycle stream follows the same visibility.
	let head = fx.lifecycle_head().await;
	for user in [in_a, in_b, in_c] {
		fx.users.set_kyc_level(user, 1, &AdminAction::system("kyc_level_set"), 0).await.unwrap();
	}
	let page = fx
		.bridge
		.pull_user_lifecycle(as_client(PullUserLifecycleRequest { after_position: head, limit: 500 }, &a))
		.await
		.unwrap()
		.into_inner();
	let seen: BTreeSet<String> = page.events.iter().map(|e| e.user_id.clone()).collect();
	assert!(seen.contains(&in_a.to_string()) && seen.contains(&in_b.to_string()));
	assert!(!seen.contains(&in_c.to_string()), "a user of a scope it does not observe is invisible");
}

#[tokio::test]
async fn lifecycle_rows_are_redacted_for_a_client_and_start_after_the_join_snapshot() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let user = fx.user("redacted").await;
	assert!(fx.sign_in(&scope, user).await);
	fx.users.set_kyc_level(user, 2, &AdminAction::system("kyc_level_set"), 0).await.unwrap();
	fx.users.set_role(user, Role::Operator).await.unwrap();

	let as_client_page = fx
		.bridge
		.pull_user_lifecycle(as_client(PullUserLifecycleRequest { after_position: 0, limit: 500 }, &scope))
		.await
		.unwrap()
		.into_inner();
	let mine: Vec<_> = as_client_page.events.iter().filter(|e| e.user_id == user.to_string()).collect();
	assert_eq!(
		mine.iter().map(|e| e.kind()).collect::<Vec<_>>(),
		[LifecycleKind::KycChanged, LifecycleKind::RoleChanged],
		"CREATED is already in the MEMBER_JOINED snapshot and is not served"
	);
	for event in &mine {
		assert!(event.seat_permissions.is_none(), "the money plane's seat set is not a direction's business");
		assert!(event.permissions.is_empty());
	}
	assert_eq!(mine[0].kyc_level, 2, "KYC level is carried (D5)");

	// From just before the user's first row: a page from 0 overflows on a shared database.
	let created = sqlx::query_scalar::<_, i64>("SELECT min(position) FROM user_outbox WHERE user_id = $1")
		.bind(user.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let bank = fx
		.bridge
		.pull_user_lifecycle(as_bridge(PullUserLifecycleRequest {
			after_position: created - 1,
			limit: 500,
		}))
		.await
		.unwrap()
		.into_inner();
	let banks: Vec<_> = bank.events.iter().filter(|e| e.user_id == user.to_string()).collect();
	assert_eq!(banks.first().map(|e| e.kind()), Some(LifecycleKind::Created), "the bridge stream is unfiltered");
	assert!(banks.iter().all(|e| e.seat_permissions.is_some()), "and unredacted");
}

#[tokio::test]
async fn member_joined_then_grants_changed_carry_snapshots_and_per_user_sequences() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let seat = fx.seat().await;
	let user = fx.user("member").await;
	let start = fx.scope_head().await;
	assert!(matches!(fx.grant(seat, user, &scope.p("operator")).await, GrantOutcome::Granted(_)));
	assert!(matches!(fx.revoke(seat, user, &scope.p("operator")).await, RevokeOutcome::Revoked));
	fx.grant(seat, user, &scope.p("operator")).await;
	fx.publish(&scope, 2, &["work:leads:read"]).await;

	let events = fx.pull_all(start, |r| as_client(r, &scope)).await;
	let mine = of_user(&events, user);
	assert_eq!(
		kinds(&mine),
		[Kind::MemberJoined, Kind::GrantsChanged, Kind::GrantsChanged, Kind::GrantsChanged, Kind::GrantsChanged]
	);
	assert_eq!(mine.iter().map(|e| e.sequence).collect::<Vec<_>>(), [1, 2, 3, 4, 5], "strictly increasing per (scope, user)");

	let row_version: i64 = sqlx::query_scalar("SELECT row_version FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let member = mine[0].member.as_ref().unwrap();
	assert!(member.email.ends_with("@scope.example.com") && member.email_verified);
	assert_eq!(member.lifecycle_sequence, row_version as u64);
	assert!(!mine[0].auth_subject.is_empty());

	let sets: Vec<Vec<String>> = mine[1..]
		.iter()
		.map(|e| e.grants.as_ref().expect("present on every GRANTS_CHANGED").permissions.clone())
		.collect();
	let mut both = vec![scope.p("work:leads:edit"), scope.p("work:leads:read")];
	both.sort();
	assert_eq!(
		sets,
		[both.clone(), vec![], both, vec![scope.p("work:leads:read")]],
		"granted, revoked to empty, regranted, narrowed by the catalog"
	);
}

#[tokio::test]
async fn a_sign_in_through_a_client_makes_the_user_visible_once() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let user = fx.user("signin").await;
	let start = fx.scope_head().await;
	assert!(fx.sign_in(&scope, user).await);
	assert!(fx.sign_in(&scope, user).await);
	let events = fx.pull_all(start, |r| as_client(r, &scope)).await;
	assert_eq!(kinds(&of_user(&events, user)), [Kind::MemberJoined], "one join, and no grants to state");
	let by: String = sqlx::query_scalar("SELECT joined_by FROM scope_members WHERE scope = $1 AND user_id = $2")
		.bind(&scope.id)
		.bind(user.raw())
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(by, "sign_in");
}

#[tokio::test]
async fn a_seat_change_restates_the_set_where_granting_seats_hold_all() {
	let Some(fx) = setup().await else { return };
	let holds_all = fx.scope(&[], true).await;
	let user = fx.user("seat-change").await;
	assert!(fx.sign_in(&holds_all, user).await);
	let start = fx.scope_head().await;
	fx.users.set_role(user, Role::Admin).await.unwrap();
	let events = fx.pull_all(start, |r| as_client(r, &holds_all)).await;
	let mine = of_user(&events, user);
	assert_eq!(kinds(&mine), [Kind::GrantsChanged]);
	assert_eq!(mine[0].grants.as_ref().unwrap().permissions.len(), 3, "a granting seat holds the whole namespace here");
}

#[tokio::test]
async fn the_stream_is_written_with_the_change_or_not_at_all() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let start = fx.scope_head().await;

	let mut tx = fx.pool.begin().await.unwrap();
	sqlx::query("UPDATE tenants SET display_name = 'Rolled back' WHERE id = $1")
		.bind(&scope.id)
		.execute(&mut *tx)
		.await
		.unwrap();
	tx.rollback().await.unwrap();
	assert!(fx.pull_all(start, |r| as_client(r, &scope)).await.is_empty(), "a rolled-back change leaves no event");

	sqlx::query("UPDATE tenants SET display_name = 'Committed' WHERE id = $1")
		.bind(&scope.id)
		.execute(&fx.pool)
		.await
		.unwrap();
	let events = fx.pull_all(start, |r| as_client(r, &scope)).await;
	assert_eq!(events.len(), 1);
	let snapshot = events[0].scope_snapshot.as_ref().unwrap();
	assert_eq!((events[0].kind(), snapshot.display_name.as_str()), (Kind::ScopeChanged, "Committed"));
	assert_eq!(events[0].sequence, snapshot.version, "SCOPE_CHANGED is ordered by the scope's version");

	let seat = fx.seat().await;
	assert!(matches!(fx.grant(seat, seat, &scope.p("operator")).await, GrantOutcome::ToSelf));
	assert!(fx.pull_all(start, |r| as_client(r, &scope)).await.len() == 1, "a refused grant makes nobody a member");
	let members: i64 = sqlx::query_scalar("SELECT count(*) FROM scope_members WHERE scope = $1")
		.bind(&scope.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(members, 0);
}

#[tokio::test]
async fn next_position_is_the_maximum_position_scanned() {
	let Some(fx) = setup().await else { return };
	let mine = fx.scope(&[], false).await;
	let other = fx.scope(&[], false).await;
	let seat = fx.seat().await;
	let start = fx.scope_head().await;
	let user = fx.user("cursor").await;
	fx.grant(seat, user, &mine.p("operator")).await;
	fx.grant(seat, fx.user("other").await, &other.p("operator")).await;
	let head = fx.scope_head().await;

	let one = fx
		.events
		.pull_scope_events(as_client(PullScopeEventsRequest { after_position: start, limit: 1 }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(one.events.len(), 1);
	assert_eq!(one.next_position, one.events[0].position, "a full page ends at its last event");

	let replay = fx
		.events
		.pull_scope_events(as_client(
			PullScopeEventsRequest {
				after_position: one.events[0].position - 1,
				limit: 1,
			},
			&mine,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(replay.events[0].event_id, one.events[0].event_id, "a parked event re-pulls as itself");

	let rest = fx
		.events
		.pull_scope_events(as_client(PullScopeEventsRequest { after_position: start, limit: 500 }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert!(rest.next_position >= head, "an unfilled page scans past rows it may not see");
	assert!(
		rest.next_position > rest.events.last().unwrap().position,
		"the other scope's rows after its last event were scanned"
	);

	let idle = fx
		.events
		.pull_scope_events(as_client(
			PullScopeEventsRequest {
				after_position: rest.next_position,
				limit: 500,
			},
			&mine,
		))
		.await
		.unwrap()
		.into_inner();
	assert!(idle.events.is_empty());
	assert!(idle.next_position >= rest.next_position);
}

#[tokio::test]
async fn a_service_credential_is_the_client_and_its_own_secret_or_the_bridge_token() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let other = fx.scope(&[], false).await;
	let pull = || PullScopeEventsRequest { after_position: 0, limit: 1 };

	assert_eq!(
		refused(fx.events.pull_scope_events(with_client(pull(), &scope.client, "wrong")).await),
		Code::Unauthenticated,
		"a short wrong secret"
	);
	assert_eq!(
		refused(fx.events.pull_scope_events(with_client(pull(), &scope.client, &other.secret)).await),
		Code::Unauthenticated,
		"another client's secret of the same length"
	);
	assert_eq!(
		refused(fx.events.pull_scope_events(with_client(pull(), "c_nobody", &scope.secret)).await),
		Code::Unauthenticated,
		"an unknown client"
	);
	let mut no_secret = Request::new(pull());
	no_secret.metadata_mut().insert("x-ev-client-id", MetadataValue::try_from(scope.client.as_str()).unwrap());
	assert_eq!(refused(fx.events.pull_scope_events(no_secret).await), Code::Unauthenticated, "a client id without a secret");
	let mut wrong_bridge = Request::new(pull());
	wrong_bridge.metadata_mut().insert("authorization", MetadataValue::try_from("Bearer not-the-token").unwrap());
	assert_eq!(refused(fx.events.pull_scope_events(wrong_bridge).await), Code::Unauthenticated, "a wrong bridge token");
	assert_eq!(
		refused(
			fx.bridge
				.pull_user_lifecycle(with_client(PullUserLifecycleRequest { after_position: 0, limit: 1 }, &scope.client, "wrong"))
				.await
		),
		Code::Unauthenticated,
		"the lifecycle stream checks the same credential"
	);

	sqlx::query("UPDATE rp_clients SET disabled_at = 1 WHERE client_id = $1")
		.bind(&scope.client)
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(
		refused(fx.events.pull_scope_events(as_client(pull(), &scope)).await),
		Code::Unauthenticated,
		"a disabled client reads no stream"
	);
	assert!(fx.events.pull_scope_events(as_client(pull(), &other)).await.is_ok());

	let unconfigured = Bridge::new(fx.pool.clone(), None);
	assert_eq!(
		refused(unconfigured.pull_user_lifecycle(as_bridge(PullUserLifecycleRequest { after_position: 0, limit: 1 })).await),
		Code::Unavailable,
		"no bridge token configured fails closed"
	);
	assert!(
		unconfigured
			.pull_user_lifecycle(as_client(PullUserLifecycleRequest { after_position: 0, limit: 1 }, &other))
			.await
			.is_ok(),
		"a client authenticates by its own secret"
	);
}

fn kind_spec(scope: &Scope) -> ApprovalKindSpec {
	ApprovalKindSpec {
		name: scope.p("valuation_override"),
		label: "Valuation override".into(),
		description: "Mark an allocation away from its computed NAV".into(),
		level: ApprovalLevel::Scope as i32,
		fields: vec![
			ApprovalFieldSpec {
				key: "allocation".into(),
				label: "Allocation".into(),
				r#type: ApprovalFieldType::Text as i32,
				required: true,
			},
			ApprovalFieldSpec {
				key: "deviation".into(),
				label: "Deviation".into(),
				r#type: ApprovalFieldType::Bps as i32,
				required: true,
			},
		],
		escalations: vec![ApprovalEscalation {
			parameter: "max_deviation".into(),
			field_key: "deviation".into(),
			test: EscalationTest::AbsBpsAbove as i32,
			default_threshold: "1000".into(),
			currency: String::new(),
		}],
		proposer: "ignored".into(),
	}
}

fn topic_spec(key: &str, label: &str) -> NotificationTopicSpec {
	NotificationTopicSpec {
		topic: key.into(),
		label: label.into(),
		description: "Marks and their reasons".into(),
		default_subscribed: false,
		required: false,
		required_reason: String::new(),
	}
}

fn publication(version: u64, kinds: Vec<ApprovalKindSpec>, topics: Vec<NotificationTopicSpec>) -> PublishScopeCatalogRequest {
	PublishScopeCatalogRequest {
		version,
		approval_kinds: kinds,
		notification_topics: topics,
	}
}

#[tokio::test]
async fn a_scope_catalog_is_kept_per_version_and_never_rolls_back() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;

	assert_eq!(code(fx.catalogs.get_scope_catalog(as_client(GetScopeCatalogRequest {}, &scope)).await), Some(Code::NotFound));

	let topic = scope.p("marks");
	let first = || publication(100, vec![kind_spec(&scope)], vec![topic_spec(&topic, "Marks")]);
	assert_eq!(code(fx.catalogs.publish_scope_catalog(as_client(first(), &scope)).await), None);
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(first(), &scope)).await),
		None,
		"republishing the same catalog is a no-op"
	);

	let got = fx.catalogs.get_scope_catalog(as_client(GetScopeCatalogRequest {}, &scope)).await.unwrap().into_inner();
	assert_eq!((got.namespace.as_str(), got.version), (scope.id.as_str(), 100));
	assert_eq!(got.approval_kinds[0].proposer, scope.id, "the proposer is the publisher's namespace, whatever the request said");
	assert_eq!(got.approval_kinds[0].escalations[0].default_threshold, "1000");
	assert_eq!(got.notification_topics[0].topic, topic);

	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(99, vec![], vec![]), &scope)).await),
		Some(Code::FailedPrecondition),
		"an older version"
	);
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(100, vec![], vec![]), &scope)).await),
		Some(Code::FailedPrecondition),
		"the same version with different content"
	);
	let ahead = now() as u64 + 2 * 24 * 60 * 60;
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(ahead, vec![], vec![]), &scope)).await),
		Some(Code::InvalidArgument)
	);
	let foreign = publication(101, vec![], vec![topic_spec("bank:marks", "Marks")]);
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(foreign, &scope)).await),
		Some(Code::InvalidArgument),
		"outside its namespace"
	);
	let mut platform = kind_spec(&scope);
	platform.level = ApprovalLevel::Platform as i32;
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![platform], vec![]), &scope)).await),
		Some(Code::InvalidArgument),
		"a platform kind escalates nowhere"
	);
	let got = fx.catalogs.get_scope_catalog(as_client(GetScopeCatalogRequest {}, &scope)).await.unwrap().into_inner();
	assert_eq!(got.version, 100, "nothing refused replaced the catalog in force");
	// Withdraw the topic: a scope topic is offered to every subscriber of the shared database.
	fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![], vec![]), &scope)).await.unwrap();

	sqlx::query("UPDATE tenants SET state = 'closed' WHERE id = $1").bind(&scope.id).execute(&fx.pool).await.unwrap();
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(102, vec![], vec![]), &scope)).await),
		Some(Code::FailedPrecondition)
	);
	assert!(
		fx.catalogs.get_scope_catalog(as_client(GetScopeCatalogRequest {}, &scope)).await.is_ok(),
		"a closed scope's history stays readable"
	);
}

/// A catalog marks at most three topics required, each with its reason; `GetScopeCatalog`
/// reads them back as published.
#[tokio::test]
async fn a_scope_catalog_marks_at_most_three_required_topics() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let required = |key: &str| NotificationTopicSpec {
		required: true,
		required_reason: "Holders are told before new fee terms bind".into(),
		..topic_spec(key, "Fee terms")
	};

	let fee_terms = scope.p("fee-terms");
	let news = scope.p("news");
	let one = publication(100, vec![], vec![required(&fee_terms), topic_spec(&news, "News")]);
	assert_eq!(code(fx.catalogs.publish_scope_catalog(as_client(one, &scope)).await), None);
	let got = fx.catalogs.get_scope_catalog(as_client(GetScopeCatalogRequest {}, &scope)).await.unwrap().into_inner();
	let flags: Vec<_> = got.notification_topics.iter().map(|t| (t.topic.as_str(), t.required, t.required_reason.is_empty())).collect();
	assert_eq!(flags, vec![(fee_terms.as_str(), true, false), (news.as_str(), false, true)]);

	let four = (0..4).map(|i| required(&scope.p(&format!("notice{i}")))).collect();
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![], four), &scope)).await),
		Some(Code::InvalidArgument),
		"over the cap"
	);
	let silent = NotificationTopicSpec {
		required_reason: String::new(),
		..required(&fee_terms)
	};
	assert_eq!(
		code(fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![], vec![silent]), &scope)).await),
		Some(Code::InvalidArgument),
		"a required topic without a reason"
	);
	let three = (0..3).map(|i| required(&scope.p(&format!("notice{i}")))).collect();
	assert_eq!(code(fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![], three), &scope)).await), None);
	fx.catalogs.publish_scope_catalog(as_client(publication(102, vec![], vec![]), &scope)).await.unwrap();
}

#[tokio::test]
async fn the_bridge_token_publishes_the_money_planes_namespace() {
	let Some(fx) = setup().await else { return };
	let version = now() as u64;
	let kind = ApprovalKindSpec {
		name: "bank:account_transfer".into(),
		label: "Transfer between accounts".into(),
		description: String::new(),
		level: ApprovalLevel::Scope as i32,
		fields: vec![ApprovalFieldSpec {
			key: "amount".into(),
			label: "Amount".into(),
			r#type: ApprovalFieldType::Amount as i32,
			required: true,
		}],
		escalations: vec![ApprovalEscalation {
			parameter: "per_operation".into(),
			field_key: "amount".into(),
			test: EscalationTest::AmountAbove as i32,
			default_threshold: "1000".into(),
			currency: "USDT".into(),
		}],
		proposer: String::new(),
	};
	match fx.catalogs.publish_scope_catalog(as_bridge(publication(version, vec![kind], vec![]))).await {
		Ok(_) => {}
		// Another run on this shared database already published a newer `bank` catalog.
		Err(status) => assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}"),
	}
	let got = fx.catalogs.get_scope_catalog(as_bridge(GetScopeCatalogRequest {})).await.unwrap().into_inner();
	assert_eq!(got.namespace, "bank");
	assert!(got.version >= version);
}

#[tokio::test]
async fn a_scope_topic_is_offered_beside_the_built_in_ones_until_withdrawn() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[], false).await;
	let notifications = PgNotifications::new(fx.pool.clone());
	let topic = scope.p("marks");
	assert!(!topic_known(&notifications, &topic).await.unwrap());

	fx.catalogs
		.publish_scope_catalog(as_client(publication(100, vec![], vec![topic_spec(&topic, "Marks")]), &scope))
		.await
		.unwrap();
	assert!(topic_known(&notifications, &topic).await.unwrap());
	assert!(topic_known(&notifications, "account:verification").await.unwrap(), "the built-in topics stay");
	let settings = settings_of(&notifications, &InboxView::All, "someone@example.com", true, None).await.unwrap();
	let offered = settings.topics.iter().find(|t| t.topic == topic).expect("offered in the settings");
	assert_eq!((offered.label.as_str(), offered.subscribed), ("Marks", false), "nobody follows a scope topic until they ask");

	fx.catalogs.publish_scope_catalog(as_client(publication(101, vec![], vec![]), &scope)).await.unwrap();
	assert!(!topic_known(&notifications, &topic).await.unwrap(), "a withdrawn topic is no longer offered");

	let reserved = publication(102, vec![], vec![topic_spec("account:verification", "Mine now")]);
	assert_eq!(
		fx.catalogs.publish_scope_catalog(as_client(reserved, &scope)).await.unwrap_err().code(),
		Code::InvalidArgument,
		"a built-in topic is outside every scope's namespace"
	);
}
