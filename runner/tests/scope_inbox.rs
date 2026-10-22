//! `ScopeInboxService` against a real Postgres: a direction's backend reads its users'
//! inbox with its client credential, and only its own namespace, only for its members.
//!
//! Every test makes its own scopes (tenant, client, secret, catalog) and its own users, so
//! the suite runs beside the others on a shared database. A write needs the user's own
//! access token for the calling client, minted here through the real code exchange and
//! verified by the real relying-party verifier against this suite's JWKS server.

use std::{net::TcpListener, sync::Arc, time::Duration};

mod common;

use concierge::{
	dispatch::{DispatcherConfig, drain_once},
	infrastructure::{
		db,
		email::transport::{EmailTransport, OutgoingEmail},
		grants::PgGrants,
		notifications::PgNotifications,
		relying_parties::PgRelyingParties,
		scope_catalogs::PgScopeCatalogs,
		users::PgUsers,
	},
	notice_link::NoticeLinkBases,
	notification::{MAX_MARK_IDS, Notifications, RateLimiter, TOPICS},
	ports::{NotificationRepository, RelyingPartyRepository, ScopeCatalogRepository, UserDirectoryRepository},
	relying_party::{Admission, ClientTokenAuthenticator, RelyingParties, Requester, s256_challenge},
	scope_inbox::{ScopeInbox, USER_TOKEN_HEADER},
	service_caller::ServiceCallers,
};
use domain::{
	error::DomainError,
	scope_catalog::{NotificationTopic, ScopeCatalog},
	users::UserId,
};
use evconcierge_auth::{AuthConfig, AuthService, Claims, SigningConfig, TokenType, Verifier, VerifierConfig, provisioner_channel};
use evconcierge_contracts::concierge::v1::{
	EmitRequest, ExchangeCodeRequest, GetScopeNotificationSettingsRequest, GetScopeUnreadCountRequest, ListScopeNotificationsRequest, MarkScopeNotificationsReadRequest,
	NotificationSettings as NotificationSettingsMsg, SetScopeTopicSubscriptionRequest,
	auth_service_server::{AuthService as AuthRpc, AuthServiceServer},
	notification_service_server::NotificationService,
	scope_inbox_service_server::ScopeInboxService,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::{
	Code, Request,
	metadata::MetadataValue,
	transport::{Channel, Server},
};
use uuid::Uuid;

const BRIDGE_TOKEN: &str = "test-bridge-token";
// The same throwaway Ed25519 keypair `relying_party.rs` and the auth crate's tests sign with.
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
const TEST_JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
const ISSUER: &str = "https://auth.concierge.test";
const CABINET: &str = "https://evinvest.ltd/cabinet";

struct Fx {
	pool: PgPool,
	callers: ServiceCallers,
	notifications: Arc<PgNotifications>,
	users: Arc<PgUsers>,
	rp: Arc<RelyingParties>,
	auth: AuthService,
	/// Where this suite's `AuthService` serves the JWKS the verifier reads.
	jwks: String,
}

struct Scope {
	id: String,
	client: String,
	secret: String,
	topic: String,
	redirect: String,
}

fn auth_config() -> AuthConfig {
	AuthConfig {
		issuer: ISSUER.into(),
		client_audience: "concierge".into(),
		service_audience: "concierge-services".into(),
		access_ttl_secs: 3600,
		refresh_ttl_secs: 3600,
		max_session_secs: 7_776_000,
		idle_timeout_secs: 0,
		service_ttl_secs: 300,
		signing: Some(SigningConfig {
			signing_key_pem: TEST_PEM.into(),
			kid: "test-kid".into(),
			jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
		}),
		google: None,
		github: None,
	}
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let callers = ServiceCallers::new(Some(BRIDGE_TOKEN.into()), Arc::new(PgRelyingParties::new(pool.clone())));
	let notifications = Arc::new(PgNotifications::new(pool.clone()));
	let users = Arc::new(PgUsers::new(pool.clone()));
	let rp = Arc::new(RelyingParties::new(
		Arc::new(PgRelyingParties::new(pool.clone())),
		users.clone(),
		Arc::new(PgGrants::new(pool.clone())),
		Default::default(),
	));
	let (provisioner, _rx) = provisioner_channel();
	let auth = AuthService::try_new(auth_config(), provisioner).await.expect("auth service").with_client_grants(rp.clone());

	let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
	let jwks = format!("http://{addr}");
	let serving = auth.clone();
	// Detached on purpose: it serves the JWKS for the life of the test's runtime and is
	// dropped with it.
	drop(tokio::spawn(async move { Server::builder().add_service(AuthServiceServer::new(serving)).serve(addr).await }));
	for attempt in 0.. {
		if Channel::from_shared(jwks.clone()).unwrap().connect().await.is_ok() {
			break;
		}
		assert!(attempt < 50, "the JWKS server never became reachable");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	Some(Fx {
		pool,
		callers,
		notifications,
		users,
		rp,
		auth,
		jwks,
	})
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

impl Fx {
	/// The service as `main` mounts it, verifying the user tokens of `clients`.
	fn inbox(&self, clients: &[&Scope]) -> ScopeInbox {
		self.inbox_with(clients, Arc::new(NoticeLinkBases::cabinet_only(CABINET)))
	}

	fn inbox_with(&self, clients: &[&Scope], links: Arc<NoticeLinkBases>) -> ScopeInbox {
		let verifier = Verifier::try_new(VerifierConfig {
			issuer: ISSUER.into(),
			audiences: clients.iter().map(|s| s.client.clone()).collect(),
			allowed_types: vec![TokenType::Access],
			jwks_grpc_endpoint: self.jwks.clone(),
		})
		.unwrap();
		ScopeInbox::new(
			self.callers.clone(),
			self.notifications.clone(),
			self.users.clone(),
			Some(ClientTokenAuthenticator::new(verifier, self.rp.clone())),
			links,
		)
	}

	/// `user`'s access token for `scope`'s client, through the real code exchange. Signing in
	/// also makes the user a member of the scope, as it does in production.
	async fn token(&self, scope: &Scope, user: Uuid) -> String {
		let client = self.rp.resolve(&scope.client, &scope.redirect).await.unwrap().expect("the client resolves");
		let Admission::Admitted { token_version } = self.rp.admit(UserId::from_raw(user)).await.unwrap() else {
			panic!("the user is admitted");
		};
		let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
		let code = self
			.rp
			.issue_code(
				&client,
				&scope.redirect,
				&s256_challenge(&verifier),
				UserId::from_raw(user),
				token_version,
				Requester {
					upstream_family: &format!("fam-{}", Uuid::new_v4()),
					auth_time: None,
					client_ip: "203.0.113.7",
					user_agent: "itest",
				},
			)
			.await
			.unwrap();
		AuthRpc::exchange_code(
			&self.auth,
			Request::new(ExchangeCodeRequest {
				client_id: scope.client.clone(),
				client_secret: scope.secret.clone(),
				code,
				redirect_uri: scope.redirect.clone(),
				code_verifier: verifier,
			}),
		)
		.await
		.expect("the code redeems")
		.into_inner()
		.access_token
	}

	/// A scope with one client, its secret and one published topic. `observers` name the
	/// clients that may read its stream.
	async fn scope(&self, observers: &[&Scope]) -> Scope {
		self.scope_publishing(observers, false).await
	}

	/// [`Self::scope`] whose topic an account that never touched it follows.
	async fn scope_publishing(&self, observers: &[&Scope], default_subscribed: bool) -> Scope {
		self.scope_catalogued(observers, default_subscribed, false).await
	}

	/// The scope's one topic as its catalog version `version` publishes it.
	async fn republish(&self, scope: &Scope, version: u64, required: bool) {
		let catalog = ScopeCatalog {
			version,
			approval_kinds: Vec::new(),
			notification_topics: vec![news(&scope.topic, false, required)],
		};
		PgScopeCatalogs::new(self.pool.clone())
			.publish(&scope.id, &scope.client, &catalog, now())
			.await
			.expect("publish the catalog");
	}

	async fn scope_catalogued(&self, observers: &[&Scope], default_subscribed: bool, required: bool) -> Scope {
		let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
		let scope = Scope {
			id: format!("x_{tag}"),
			client: format!("xc_{tag}"),
			secret: format!("{tag}{tag}{tag}"),
			topic: format!("x_{tag}:news"),
			redirect: format!("https://{tag}.test/cb"),
		};
		let observers: Vec<String> = observers.iter().map(|s| s.client.clone()).collect();
		sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, observers) VALUES ($1, $1, FALSE, 0, $2)")
			.bind(&scope.id)
			.bind(&observers)
			.execute(&self.pool)
			.await
			.expect("register the scope");
		sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, created_at, tenant_id) VALUES ($1, $1, $2, 0, $3)")
			.bind(&scope.client)
			.bind(vec![scope.redirect.clone()])
			.bind(&scope.id)
			.execute(&self.pool)
			.await
			.expect("register the client");
		PgRelyingParties::new(self.pool.clone())
			.set_secret_hash(&scope.client, Some(Sha256::digest(scope.secret.as_bytes()).as_slice()), 0)
			.await
			.expect("set the secret");
		let catalog = ScopeCatalog {
			version: 1,
			approval_kinds: Vec::new(),
			notification_topics: vec![news(&scope.topic, default_subscribed, required)],
		};
		PgScopeCatalogs::new(self.pool.clone())
			.publish(&scope.id, &scope.client, &catalog, now())
			.await
			.expect("publish the catalog");
		scope
	}

	async fn user(&self, tag: &str) -> (Uuid, String) {
		let user = self.users.resolve(common::google(tag, true), 0).await.unwrap();
		(user.id().raw(), user.email().as_str().to_owned())
	}

	async fn join(&self, scope: &Scope, user: Uuid) {
		sqlx::query(
			"INSERT INTO scope_members (scope, user_id, joined_at, joined_by, lifecycle_sequence, sequence, permissions) VALUES ($1, $2, 0, 'grant', 0, 1, '{}') ON CONFLICT DO NOTHING",
		)
		.bind(&scope.id)
		.bind(user)
		.execute(&self.pool)
		.await
		.expect("make the user a member");
	}

	/// An inbox entry on `topic`, written as a consent trace is: regardless of follows.
	async fn note(&self, user: Uuid, email: &str, topic: &str) -> Uuid {
		let dedupe = Uuid::new_v4().to_string();
		assert!(self.notifications.record(user, email, true, topic, "k", "t", "", &dedupe, now()).await.unwrap());
		sqlx::query_scalar("SELECT n.id FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.dedupe_key = $2")
			.bind(user)
			.bind(&dedupe)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	async fn unread_rows(&self, user: Uuid) -> i64 {
		sqlx::query_scalar("SELECT count(*) FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.read_at IS NULL")
			.bind(user)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}
}

const REASON: &str = "Holders are told before new fee terms bind";

/// The one topic every test scope publishes.
fn news(topic: &str, default_subscribed: bool, required: bool) -> NotificationTopic {
	NotificationTopic {
		topic: topic.to_owned(),
		label: "News".into(),
		description: String::new(),
		default_subscribed,
		required,
		required_reason: if required { REASON.into() } else { String::new() },
	}
}

fn with_client<T>(body: T, client: &str, secret: &str) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("x-ev-client-id", MetadataValue::try_from(client).unwrap());
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {secret}")).unwrap());
	request
}

fn as_client<T>(body: T, scope: &Scope) -> Request<T> {
	with_client(body, &scope.client, &scope.secret)
}

/// `scope`'s client writing for the user `token` was issued for.
fn on_behalf<T>(body: T, scope: &Scope, token: &str) -> Request<T> {
	let mut request = as_client(body, scope);
	request.metadata_mut().insert(USER_TOKEN_HEADER, MetadataValue::try_from(token).unwrap());
	request
}

fn follow(user: &str, topic: &str) -> SetScopeTopicSubscriptionRequest {
	SetScopeTopicSubscriptionRequest {
		user_id: user.to_owned(),
		topic: topic.to_owned(),
		subscribed: true,
		email_enabled: true,
	}
}

fn mark_all(user: &str) -> MarkScopeNotificationsReadRequest {
	MarkScopeNotificationsReadRequest {
		user_id: user.to_owned(),
		ids: Vec::new(),
		all: true,
	}
}

fn list(user: Uuid) -> ListScopeNotificationsRequest {
	ListScopeNotificationsRequest {
		user_id: user.to_string(),
		..Default::default()
	}
}

#[tokio::test]
async fn a_member_reads_only_the_scope_namespace_in_pages() {
	let Some(fx) = setup().await else { return };
	let mine = fx.scope(&[]).await;
	let other = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&mine, &other]);
	let (user, email) = fx.user("member").await;
	let token = fx.token(&mine, user).await;
	fx.join(&other, user).await;
	for _ in 0..25 {
		fx.note(user, &email, &mine.topic).await;
	}
	fx.note(user, &email, &other.topic).await;
	fx.note(user, &email, TOPICS[2].key).await;
	fx.note(user, &email, "bank:anything").await;

	let page = inbox.list_scope_notifications(as_client(list(user), &mine)).await.unwrap().into_inner();
	assert_eq!(page.notifications.len(), 20, "limit 0 is a real page, not one row");
	assert!(page.notifications.iter().all(|n| n.topic == mine.topic), "only this scope's namespace");
	assert!(!page.next_cursor.is_empty());
	assert_eq!(page.unread_count, 25);
	let rest = inbox
		.list_scope_notifications(as_client(
			ListScopeNotificationsRequest {
				user_id: user.to_string(),
				cursor: page.next_cursor,
				limit: 50,
				..Default::default()
			},
			&mine,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((rest.notifications.len(), rest.next_cursor.as_str()), (5, ""));

	let unread = inbox
		.get_scope_unread_count(as_client(GetScopeUnreadCountRequest { user_id: user.to_string() }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(unread.unread_count, 25);

	let settings = inbox
		.get_scope_notification_settings(as_client(GetScopeNotificationSettingsRequest { user_id: user.to_string() }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(settings.topics.iter().map(|t| t.topic.as_str()).collect::<Vec<_>>(), vec![mine.topic.as_str()]);
	assert_eq!(settings.email, email, "a member's own address, which the scope's stream already carries");

	// The token names the user; `user_id` may be left out of a write.
	let followed = inbox.set_scope_topic_subscription(on_behalf(follow("", &mine.topic), &mine, &token)).await.unwrap().into_inner();
	assert!(followed.topics.iter().any(|t| t.topic == mine.topic && t.subscribed && t.email_enabled));

	let all = inbox
		.mark_scope_notifications_read(on_behalf(mark_all(&user.to_string()), &mine, &token))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((all.marked, all.unread_count), (25, 0));
	assert_eq!(fx.unread_rows(user).await, 3, "the other scope's, the built-in and the bank's stay unread");
}

#[tokio::test]
async fn a_non_member_reads_nothing() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope]);
	let (user, email) = fx.user("outsider").await;
	fx.note(user, &email, &scope.topic).await;

	let disabled = fx.user("disabled").await.0;
	fx.join(&scope, disabled).await;
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(disabled).execute(&fx.pool).await.unwrap();

	for id in [user, disabled, Uuid::new_v4()] {
		let page = inbox.list_scope_notifications(as_client(list(id), &scope)).await.unwrap().into_inner();
		assert!(page.notifications.is_empty() && page.unread_count == 0, "{id}");
		let unread = inbox
			.get_scope_unread_count(as_client(GetScopeUnreadCountRequest { user_id: id.to_string() }, &scope))
			.await
			.unwrap()
			.into_inner();
		assert_eq!(unread.unread_count, 0);
		let settings = inbox
			.get_scope_notification_settings(as_client(GetScopeNotificationSettingsRequest { user_id: id.to_string() }, &scope))
			.await
			.unwrap()
			.into_inner();
		assert_eq!(settings, Default::default(), "not even whose address the id is: {id}");
	}
}

/// A client secret alone writes nothing: following a topic turns on mail to someone's
/// address, so the user's own token for THIS client is what names them.
#[tokio::test]
async fn a_write_needs_the_user_s_token_for_this_client() {
	let Some(fx) = setup().await else { return };
	let mine = fx.scope(&[]).await;
	let other = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&mine, &other]);
	let (user, email) = fx.user("writer").await;
	let token = fx.token(&mine, user).await;
	let theirs = fx.token(&other, user).await;
	let (someone, _) = fx.user("someone").await;
	fx.token(&mine, someone).await;
	fx.note(user, &email, &mine.topic).await;
	let me = user.to_string();

	let bare = inbox.set_scope_topic_subscription(as_client(follow(&me, &mine.topic), &mine)).await.unwrap_err();
	assert_eq!(bare.code(), Code::Unauthenticated, "no token, no write");
	let bare = inbox.mark_scope_notifications_read(as_client(mark_all(&me), &mine)).await.unwrap_err();
	assert_eq!(bare.code(), Code::Unauthenticated);

	let forged = inbox.set_scope_topic_subscription(on_behalf(follow(&me, &mine.topic), &mine, "not.a.token")).await.unwrap_err();
	assert_eq!(forged.code(), Code::Unauthenticated);

	let foreign = inbox.set_scope_topic_subscription(on_behalf(follow(&me, &mine.topic), &mine, &theirs)).await.unwrap_err();
	assert_eq!(foreign.code(), Code::PermissionDenied, "a token issued to another client");
	let foreign = inbox.mark_scope_notifications_read(on_behalf(mark_all(&me), &mine, &theirs)).await.unwrap_err();
	assert_eq!(foreign.code(), Code::PermissionDenied);

	let other_user = inbox
		.set_scope_topic_subscription(on_behalf(follow(&someone.to_string(), &mine.topic), &mine, &token))
		.await
		.unwrap_err();
	assert_eq!(other_user.code(), Code::PermissionDenied, "user_id names someone the token does not speak for");
	let other_user = inbox.mark_scope_notifications_read(on_behalf(mark_all(&someone.to_string()), &mine, &token)).await.unwrap_err();
	assert_eq!(other_user.code(), Code::PermissionDenied);
	assert_eq!(fx.unread_rows(user).await, 1, "nothing was marked by a refused write");

	let too_many = MarkScopeNotificationsReadRequest {
		user_id: me.clone(),
		ids: (0..=MAX_MARK_IDS).map(|_| Uuid::new_v4().to_string()).collect(),
		all: false,
	};
	assert_eq!(
		inbox.mark_scope_notifications_read(on_behalf(too_many, &mine, &token)).await.unwrap_err().code(),
		Code::InvalidArgument
	);
	let at_most = MarkScopeNotificationsReadRequest {
		user_id: me.clone(),
		ids: (0..MAX_MARK_IDS).map(|_| Uuid::new_v4().to_string()).collect(),
		all: false,
	};
	assert_eq!(inbox.mark_scope_notifications_read(on_behalf(at_most, &mine, &token)).await.unwrap().into_inner().marked, 0);

	inbox
		.set_scope_topic_subscription(on_behalf(follow(&me, &mine.topic), &mine, &token))
		.await
		.expect("the user's own token writes");
	assert_eq!(inbox.mark_scope_notifications_read(on_behalf(mark_all(&me), &mine, &token)).await.unwrap().into_inner().marked, 1);

	// A token that still verifies, for an account suspended since: not a member any more.
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(user).execute(&fx.pool).await.unwrap();
	let held = inbox.set_scope_topic_subscription(on_behalf(follow(&me, &mine.topic), &mine, &token)).await.unwrap_err();
	assert_eq!(held.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn only_the_scope_s_own_client_opens_it() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let closed = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope, &closed]);
	let (user, _) = fx.user("creds").await;
	fx.join(&scope, user).await;

	let wrong = inbox.list_scope_notifications(with_client(list(user), &scope.client, "not-the-secret")).await.unwrap_err();
	assert_eq!(wrong.code(), Code::Unauthenticated);
	let unknown = inbox.list_scope_notifications(with_client(list(user), "nobody_here", &scope.secret)).await.unwrap_err();
	assert_eq!(unknown.code(), Code::Unauthenticated);
	let anonymous = inbox.list_scope_notifications(Request::new(list(user))).await.unwrap_err();
	assert_eq!(anonymous.code(), Code::Unauthenticated);

	let mut bridge = Request::new(list(user));
	bridge.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {BRIDGE_TOKEN}")).unwrap());
	assert_eq!(inbox.list_scope_notifications(bridge).await.unwrap_err().code(), Code::PermissionDenied);

	sqlx::query("UPDATE rp_clients SET disabled_at = 0 WHERE client_id = $1")
		.bind(&scope.client)
		.execute(&fx.pool)
		.await
		.unwrap();
	let disabled = inbox.list_scope_notifications(as_client(list(user), &scope)).await.unwrap_err();
	assert_eq!(disabled.code(), Code::Unauthenticated);

	fx.join(&closed, user).await;
	sqlx::query("UPDATE tenants SET state = 'closed' WHERE id = $1").bind(&closed.id).execute(&fx.pool).await.unwrap();
	let refused = inbox.list_scope_notifications(as_client(list(user), &closed)).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition);
}

/// An observer reads a scope's stream, never its users' inbox: the namespace is always the
/// caller's own.
#[tokio::test]
async fn a_client_never_reaches_another_scope_s_inbox_even_as_its_observer() {
	let Some(fx) = setup().await else { return };
	let a = fx.scope(&[]).await;
	let b = fx.scope(&[&a]).await;
	let inbox = fx.inbox(&[&a, &b]);
	let (user, email) = fx.user("both").await;
	let token = fx.token(&a, user).await;
	fx.join(&b, user).await;
	let of_b = fx.note(user, &email, &b.topic).await;

	let page = inbox.list_scope_notifications(as_client(list(user), &a)).await.unwrap().into_inner();
	assert!(page.notifications.is_empty(), "{:?}", page.notifications);
	let filter = inbox
		.list_scope_notifications(as_client(
			ListScopeNotificationsRequest {
				user_id: user.to_string(),
				topic: b.topic.clone(),
				..Default::default()
			},
			&a,
		))
		.await
		.unwrap_err();
	assert_eq!(filter.code(), Code::InvalidArgument);

	let marked = inbox
		.mark_scope_notifications_read(on_behalf(
			MarkScopeNotificationsReadRequest {
				user_id: user.to_string(),
				ids: vec![of_b.to_string()],
				all: false,
			},
			&a,
			&token,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(marked.marked, 0, "another inbox's id is not marked");
	assert_eq!(fx.unread_rows(user).await, 1);

	let follow_b = inbox.set_scope_topic_subscription(on_behalf(follow(&user.to_string(), &b.topic), &a, &token)).await.unwrap_err();
	assert_eq!(follow_b.code(), Code::InvalidArgument);

	let own = inbox.list_scope_notifications(as_client(list(user), &b)).await.unwrap().into_inner();
	assert_eq!(own.notifications.iter().map(|n| n.id.clone()).collect::<Vec<_>>(), vec![of_b.to_string()]);
}

fn emit(user: Uuid, topic: &str) -> EmitRequest {
	EmitRequest {
		user_id: user.to_string(),
		topic: topic.to_owned(),
		kind: "news".into(),
		title: "Something happened".into(),
		dedupe_key: Uuid::new_v4().to_string(),
		..Default::default()
	}
}

fn as_bridge<T>(body: T) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {BRIDGE_TOKEN}")).unwrap());
	request
}

impl Fx {
	async fn follow(&self, user: Uuid, email: &str, topic: &str) {
		let sub = self.notifications.subscriber_for_user(user, email, true).await.unwrap();
		self.notifications.set_topic_subscription(sub.id, topic, true, true).await.unwrap();
	}

	async fn rows_on(&self, user: Uuid, topic: &str) -> i64 {
		sqlx::query_scalar("SELECT count(*) FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.topic = $2")
			.bind(user)
			.bind(topic)
			.fetch_one(&self.pool)
			.await
			.unwrap()
	}

	/// `topics` added to the bank's catalog in force, keeping what it already publishes: the
	/// namespace is shared by every suite on the database.
	async fn publish_bank(&self, topics: &[NotificationTopic]) {
		let catalogs = PgScopeCatalogs::new(self.pool.clone());
		loop {
			if let Some(current) = catalogs.current("bank").await.unwrap()
				&& topics.iter().all(|t| current.notification_topics.contains(t))
			{
				return;
			}
			let mut catalog = catalogs.current("bank").await.unwrap().unwrap_or(ScopeCatalog {
				version: 0,
				approval_kinds: Vec::new(),
				notification_topics: Vec::new(),
			});
			catalog.notification_topics.retain(|t| topics.iter().all(|mine| mine.topic != t.topic));
			catalog.notification_topics.extend(topics.iter().cloned());
			catalog.version = catalog.version.max(now() as u64) + 1;
			catalogs.publish("bank", "bridge", &catalog, now()).await.unwrap();
			let current = catalogs.current("bank").await.unwrap().unwrap();
			if topics.iter().all(|t| current.notification_topics.contains(t)) {
				return;
			}
		}
	}
}

/// A service emits on its own namespace's published topics only, and only to the scope's
/// members: the client credential is what binds it to a namespace.
#[tokio::test]
async fn a_service_emits_only_its_own_namespace_s_published_topics_to_members() {
	let Some(fx) = setup().await else { return };
	let mine = fx.scope(&[]).await;
	let other = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&mine, &other]);
	let (member, email) = fx.user("emit-member").await;
	fx.join(&mine, member).await;
	fx.follow(member, &email, &mine.topic).await;
	let (outsider, outsider_email) = fx.user("emit-outsider").await;
	fx.follow(outsider, &outsider_email, &mine.topic).await;

	let sent = inbox.emit_scope_notification(as_client(emit(member, &mine.topic), &mine)).await.unwrap().into_inner();
	assert!(sent.delivered && !sent.notification_id.is_empty(), "{sent:?}");
	assert_eq!(sent.channels, vec![1, 2], "in-app and the mail copy of a verified address");
	assert_eq!(fx.rows_on(member, &mine.topic).await, 1);

	let stranger = inbox.emit_scope_notification(as_client(emit(outsider, &mine.topic), &mine)).await.unwrap().into_inner();
	assert!(
		!stranger.delivered && stranger.notification_id.is_empty(),
		"a follower outside the scope gets nothing: {stranger:?}"
	);
	assert_eq!(fx.rows_on(outsider, &mine.topic).await, 0, "and nothing is written for them");

	for (topic, code) in [
		(other.topic.as_str(), Code::PermissionDenied),
		(TOPICS[0].key, Code::PermissionDenied),
		("bank:anything", Code::PermissionDenied),
		(&*format!("{}:unpublished", mine.id), Code::InvalidArgument),
	] {
		let refused = inbox.emit_scope_notification(as_client(emit(member, topic), &mine)).await.unwrap_err();
		assert_eq!(refused.code(), code, "{topic}: {refused:?}");
	}
	let mut bad = emit(member, &mine.topic);
	bad.title.clear();
	assert_eq!(inbox.emit_scope_notification(as_client(bad, &mine)).await.unwrap_err().code(), Code::InvalidArgument);

	let wrong = inbox
		.emit_scope_notification(with_client(emit(member, &mine.topic), &mine.client, "not-the-secret"))
		.await
		.unwrap_err();
	assert_eq!(wrong.code(), Code::Unauthenticated);
	sqlx::query("UPDATE tenants SET state = 'closed' WHERE id = $1").bind(&mine.id).execute(&fx.pool).await.unwrap();
	let closed = inbox.emit_scope_notification(as_client(emit(member, &mine.topic), &mine)).await.unwrap_err();
	assert_eq!(closed.code(), Code::FailedPrecondition);
	assert_eq!(fx.rows_on(member, &mine.topic).await, 1, "no refused emit wrote anything");

	// A `typ=service` token names no namespace, so it reaches no scope's topic at all.
	let service = Notifications::new(
		fx.notifications.clone(),
		fx.users.clone(),
		Arc::new(RateLimiter::new(Duration::from_secs(60), 10)),
		Arc::new(NoticeLinkBases::cabinet_only(CABINET)),
	);
	let mut unbound = Request::new(emit(member, &other.topic));
	unbound.extensions_mut().insert(Claims {
		iss: ISSUER.into(),
		sub: "some-service".into(),
		aud: "concierge-services".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Service,
		jti: None,
		token_version: 0,
		auth_time: None,
	});
	assert_eq!(service.emit(unbound).await.unwrap_err().code(), Code::PermissionDenied);
}

/// The bridge token speaks for `bank`, whose topics the platform inbox shows to every
/// account: no membership to hold it to.
#[tokio::test]
async fn the_bridge_emits_the_bank_s_published_topics_to_anyone_following_them() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope]);
	let topic = "bank:emit_test".to_owned();
	fx.publish_bank(&[NotificationTopic {
		topic: topic.clone(),
		label: "Money".into(),
		description: String::new(),
		default_subscribed: false,
		required: false,
		required_reason: String::new(),
	}])
	.await;
	let (user, email) = fx.user("bank-follower").await;
	fx.follow(user, &email, &topic).await;

	let sent = inbox.emit_scope_notification(as_bridge(emit(user, &topic))).await.unwrap().into_inner();
	assert!(sent.delivered, "{sent:?}");
	assert_eq!(fx.rows_on(user, &topic).await, 1);

	for foreign in [scope.topic.as_str(), "bank:not_published", TOPICS[0].key] {
		let refused = inbox.emit_scope_notification(as_bridge(emit(user, foreign))).await.unwrap_err();
		assert!(matches!(refused.code(), Code::PermissionDenied | Code::InvalidArgument), "{foreign}: {refused:?}");
	}
	assert_eq!(
		inbox.emit_scope_notification(as_bridge(emit(user, &scope.topic))).await.unwrap_err().code(),
		Code::PermissionDenied,
		"a scope's topic is not the bank's"
	);
	assert_eq!(
		inbox.emit_scope_notification(as_bridge(emit(user, "bank:not_published"))).await.unwrap_err().code(),
		Code::InvalidArgument
	);
	// The bridge still reads no scope's inbox.
	assert_eq!(inbox.list_scope_notifications(as_bridge(list(user))).await.unwrap_err().code(), Code::PermissionDenied);
}

#[derive(Default)]
struct Outbox(std::sync::Mutex<Vec<OutgoingEmail>>);

#[async_trait::async_trait]
impl EmailTransport for Outbox {
	async fn send(&self, _from: &str, email: OutgoingEmail) -> Result<(), DomainError> {
		self.0.lock().unwrap().push(email);
		Ok(())
	}
}

/// banking#580: a notice for a scope with a configured base links to that scope's
/// cabinet, in the inbox row and in the mail; one without `link_scope` still links under
/// `CABINET_URL`, and an emitter never gets to name a host itself.
#[tokio::test]
async fn a_notice_for_a_scope_links_to_that_scope_s_cabinet() {
	let Some(fx) = setup().await else { return };
	let bases = Arc::new(NoticeLinkBases::parse(&["invest=https://invest.evinvest.ltd/cabinet".to_owned()], CABINET, "https://evinvest.ltd", true).unwrap());
	let scope = fx.scope(&[]).await;
	let inbox = fx.inbox_with(&[&scope], bases.clone());
	// The topic of the bridge test beside it: each new `bank` topic bumps the shared
	// catalog's version past the clock, which `scoped_inbox`'s publication must beat.
	let topic = "bank:emit_test".to_owned();
	fx.publish_bank(&[NotificationTopic {
		topic: topic.clone(),
		label: "Money".into(),
		description: String::new(),
		default_subscribed: false,
		required: false,
		required_reason: String::new(),
	}])
	.await;
	let (user, email) = fx.user("link-scope").await;
	fx.follow(user, &email, &topic).await;

	let notice = |link_scope: &str, title: &str| EmitRequest {
		link: "/wallet/action/payment/42".into(),
		link_scope: link_scope.into(),
		title: title.into(),
		..emit(user, &topic)
	};
	for (link_scope, title) in [("invest", "scoped"), ("", "unscoped"), ("sa", "no base")] {
		let sent = inbox.emit_scope_notification(as_bridge(notice(link_scope, title))).await.unwrap().into_inner();
		assert!(sent.delivered, "{link_scope:?}: {sent:?}");
	}
	let stored: Vec<(String, String)> =
		sqlx::query_as("SELECT n.title, n.link FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.topic = $2 ORDER BY n.title")
			.bind(user)
			.bind(&topic)
			.fetch_all(&fx.pool)
			.await
			.unwrap();
	assert_eq!(
		stored,
		vec![
			("no base".to_owned(), "/wallet/action/payment/42".to_owned()),
			("scoped".to_owned(), "https://invest.evinvest.ltd/cabinet/wallet/action/payment/42".to_owned()),
			("unscoped".to_owned(), "/wallet/action/payment/42".to_owned()),
		]
	);

	for (link, link_scope) in [("https://attacker.example/x", ""), ("//attacker.example", "invest"), ("/wallet", "In-vest")] {
		let mut bad = notice(link_scope, "refused");
		bad.link = link.into();
		let refused = inbox.emit_scope_notification(as_bridge(bad)).await.unwrap_err();
		assert_eq!(refused.code(), Code::InvalidArgument, "{link:?} / {link_scope:?}: {refused:?}");
	}

	let outbox = Outbox::default();
	let cfg = DispatcherConfig {
		mail_from: "EV <noreply@evinvest.test>".into(),
		notice_links: bases,
		public_origin: "https://evinvest.ltd".into(),
		approvals_url: "https://evinvest.ltd/admin/approvals".into(),
		daily_budget: i64::MAX,
		interval: Duration::from_secs(60),
	};
	while drain_once(&PgNotifications::new(fx.pool.clone()), &outbox, &cfg).await > 0 {}
	let mails: Vec<OutgoingEmail> = outbox.0.lock().unwrap().iter().filter(|m| m.to == email).cloned().collect();
	let target = |title: &str| {
		let mail = mails.iter().find(|m| m.subject.ends_with(title)).unwrap_or_else(|| panic!("the {title:?} mail was sent"));
		mail.text
			.lines()
			.find_map(|line| line.strip_prefix("Open your cabinet: "))
			.expect("the text part carries the link")
			.to_owned()
	};
	assert_eq!(target("— scoped"), "https://invest.evinvest.ltd/cabinet/wallet/action/payment/42");
	assert_eq!(target("— unscoped"), "https://evinvest.ltd/cabinet/wallet/action/payment/42");
	assert_eq!(target("— no base"), "https://evinvest.ltd/cabinet/wallet/action/payment/42");
}

/// A relying party links only into its own scope's cabinet; only the bridge names another.
#[tokio::test]
async fn a_client_names_only_its_own_scope_as_link_scope() {
	let Some(fx) = setup().await else { return };
	let sa = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&sa]);
	let (member, email) = fx.user("link-scope-client").await;
	fx.join(&sa, member).await;
	fx.follow(member, &email, &sa.topic).await;

	let mut foreign = emit(member, &sa.topic);
	foreign.link = "/wallet".into();
	foreign.link_scope = "invest".into();
	assert_eq!(inbox.emit_scope_notification(as_client(foreign, &sa)).await.unwrap_err().code(), Code::PermissionDenied);
	assert_eq!(fx.rows_on(member, &sa.topic).await, 0, "nothing is written");

	let mut own = emit(member, &sa.topic);
	own.link = "/wallet".into();
	own.link_scope = sa.id.clone();
	assert!(inbox.emit_scope_notification(as_client(own, &sa)).await.unwrap().into_inner().delivered);
}

/// A row written before the emit rule held only a length check, or under a base removed
/// since, reaches the reader without its link: a cabinet renders an absolute one as given.
#[tokio::test]
async fn an_inbox_read_drops_a_stored_link_under_no_configured_cabinet() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope]);
	let (user, email) = fx.user("inbox-link").await;
	fx.join(&scope, user).await;
	let hostile = ["https://phish.example/login", "javascript:alert(1)", "https://invest.evinvest.ltd/cabinet/wallet"];
	let kept = ["/wallet", "https://evinvest.ltd/cabinet/x"];
	for link in hostile.iter().chain(kept.iter()) {
		let id = fx.note(user, &email, &scope.topic).await;
		sqlx::query("UPDATE notifications SET link = $2 WHERE id = $1")
			.bind(id)
			.bind(link)
			.execute(&fx.pool)
			.await
			.unwrap();
	}
	let page = inbox.list_scope_notifications(as_client(list(user), &scope)).await.unwrap().into_inner();
	let mut links: Vec<String> = page.notifications.into_iter().map(|n| n.link).collect();
	links.sort();
	assert_eq!(links, vec!["", "", "", "/wallet", "https://evinvest.ltd/cabinet/x"], "no base is configured here");
}

fn unfollow(topic: &str) -> SetScopeTopicSubscriptionRequest {
	SetScopeTopicSubscriptionRequest {
		user_id: String::new(),
		topic: topic.to_owned(),
		subscribed: false,
		email_enabled: false,
	}
}

/// `default_subscribed` follows the topic for an account that never touched it, and an
/// unsubscribe is remembered — a row of its own — so "switched off" stays off.
#[tokio::test]
async fn a_default_topic_reaches_members_who_never_touched_it_until_they_switch_it_off() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope_publishing(&[], true).await;
	let quiet = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope, &quiet]);
	let (user, _) = fx.user("default-topic").await;
	let token = fx.token(&scope, user).await;
	fx.join(&quiet, user).await;
	let settings = |fx_scope: &Scope| as_client(GetScopeNotificationSettingsRequest { user_id: user.to_string() }, fx_scope);
	let stance = |s: &NotificationSettingsMsg, topic: &str| s.topics.iter().find(|t| t.topic == topic).map(|t| (t.subscribed, t.email_enabled));

	let before = inbox.get_scope_notification_settings(settings(&scope)).await.unwrap().into_inner();
	assert_eq!(stance(&before, &scope.topic), Some((true, true)), "never touched: followed, mail on");
	let sent = inbox.emit_scope_notification(as_client(emit(user, &scope.topic), &scope)).await.unwrap().into_inner();
	assert_eq!((sent.delivered, sent.channels.clone()), (true, vec![1, 2]), "{sent:?}");

	let not_default = inbox.emit_scope_notification(as_client(emit(user, &quiet.topic), &quiet)).await.unwrap().into_inner();
	assert!(!not_default.delivered, "a topic published without the default reaches only who follows it");

	inbox.set_scope_topic_subscription(on_behalf(unfollow(&scope.topic), &scope, &token)).await.unwrap();
	let (rows, optouts): (i64, i64) = sqlx::query_as(
		"SELECT (SELECT count(*) FROM notification_subscriptions WHERE subscriber_id = s.id AND topic = $2), \
		        (SELECT count(*) FROM notification_topic_optouts WHERE subscriber_id = s.id AND topic = $2) \
		 FROM notification_subscribers s WHERE s.user_id = $1",
	)
	.bind(user)
	.bind(&scope.topic)
	.fetch_one(&fx.pool)
	.await
	.unwrap();
	assert_eq!((rows, optouts), (0, 1), "switched off is a row of its own, not a missing one");
	let after = inbox.get_scope_notification_settings(settings(&scope)).await.unwrap().into_inner();
	assert_eq!(stance(&after, &scope.topic).map(|s| s.0), Some(false), "and reads as switched off");
	let muted = inbox.emit_scope_notification(as_client(emit(user, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(!muted.delivered && muted.notification_id.is_empty(), "{muted:?}");

	inbox.set_scope_topic_subscription(on_behalf(follow("", &scope.topic), &scope, &token)).await.unwrap();
	let back = inbox.emit_scope_notification(as_client(emit(user, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(back.delivered, "following again lifts the opt-out");
	assert_eq!(fx.rows_on(user, &scope.topic).await, 2);
}

/// A required topic reaches every active member whatever they chose — an opt-out stored
/// before it became required, both master switches off — in-app always and by mail to a
/// verified address; a member cannot switch it off; nobody outside the scope gets it; and
/// once a later catalog makes it ordinary again, the member's stored choice counts again.
#[tokio::test]
async fn a_required_topic_reaches_every_member_whatever_they_chose() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let inbox = fx.inbox(&[&scope]);
	let (member, _) = fx.user("required-member").await;
	let token = fx.token(&scope, member).await;
	let settings = || as_client(GetScopeNotificationSettingsRequest { user_id: member.to_string() }, &scope);
	let stance = |s: &NotificationSettingsMsg| {
		let t = s.topics.iter().find(|t| t.topic == scope.topic).expect("the topic is offered");
		(t.subscribed, t.email_enabled, t.required, t.required_reason.clone())
	};
	let optouts = || async {
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_topic_optouts o JOIN notification_subscribers s ON s.id = o.subscriber_id WHERE s.user_id = $1 AND o.topic = $2")
			.bind(member)
			.bind(&scope.topic)
			.fetch_one(&fx.pool)
			.await
			.unwrap()
	};

	// Switched off while the topic was ordinary: nothing reaches the member.
	inbox.set_scope_topic_subscription(on_behalf(unfollow(&scope.topic), &scope, &token)).await.unwrap();
	assert!(!inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner().delivered);

	fx.republish(&scope, 2, true).await;
	let read = inbox.get_scope_notification_settings(settings()).await.unwrap().into_inner();
	assert_eq!(stance(&read), (true, true, true, REASON.to_owned()), "shown as on and locked, with the reason");
	let sent = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert_eq!((sent.delivered, sent.channels), (true, vec![1, 2]), "the old opt-out is ignored");
	assert_eq!(optouts().await, 1, "and kept, untouched");

	for (subscribed, email_enabled) in [(false, false), (true, false)] {
		let change = SetScopeTopicSubscriptionRequest {
			user_id: String::new(),
			topic: scope.topic.clone(),
			subscribed,
			email_enabled,
		};
		let refused = inbox.set_scope_topic_subscription(on_behalf(change, &scope, &token)).await.unwrap_err();
		assert_eq!(refused.code(), Code::FailedPrecondition, "{subscribed}/{email_enabled}: {refused:?}");
		assert!(refused.message().starts_with("required_topic:"), "{refused:?}");
	}

	// Both master switches off: the notice is still written, mailed and shown.
	let sub = fx.notifications.subscriber_of_user(member).await.unwrap().expect("a subscriber row");
	fx.notifications.set_channel_enabled(sub.id, Some(false), Some(false)).await.unwrap();
	let sent = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert_eq!((sent.delivered, sent.channels), (true, vec![1, 2]), "neither master switch silences it");
	let page = inbox.list_scope_notifications(as_client(list(member), &scope)).await.unwrap().into_inner();
	assert_eq!(page.notifications.len(), 2, "the in-app switch does not hide a required notice: {page:?}");
	assert!(page.notifications.iter().all(|n| n.topic == scope.topic));
	assert_eq!(page.unread_count, 2);
	let unread = inbox
		.get_scope_unread_count(as_client(GetScopeUnreadCountRequest { user_id: member.to_string() }, &scope))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(unread.unread_count, 2);
	let mails: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_deliveries WHERE subscriber_id = $1 AND kind = 'notification'")
		.bind(sub.id)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(mails, 2, "both required notices queued a mail");

	// An address nobody proved gets no mail, and the notice is still delivered in-app.
	let unverified = fx.users.resolve(common::google("required-unverified", false), 0).await.unwrap().id().raw();
	fx.join(&scope, unverified).await;
	let sent = inbox.emit_scope_notification(as_client(emit(unverified, &scope.topic), &scope)).await.unwrap().into_inner();
	assert_eq!((sent.delivered, sent.channels), (true, vec![1]), "in-app only");

	// Nobody outside the scope.
	let (outsider, _) = fx.user("required-outsider").await;
	let stranger = inbox.emit_scope_notification(as_client(emit(outsider, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(!stranger.delivered && stranger.notification_id.is_empty(), "{stranger:?}");
	assert_eq!(fx.rows_on(outsider, &scope.topic).await, 0);

	// Ordinary again: the opt-out the member left stands, and the in-app switch hides the inbox.
	fx.republish(&scope, 3, false).await;
	let read = inbox.get_scope_notification_settings(settings()).await.unwrap().into_inner();
	assert!(!stance(&read).0, "switched off, as the member left it");
	assert_eq!((read.topics[0].required, read.topics[0].required_reason.as_str()), (false, ""));
	let muted = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(!muted.delivered, "{muted:?}");
	let page = inbox.list_scope_notifications(as_client(list(member), &scope)).await.unwrap().into_inner();
	assert!(page.notifications.is_empty(), "{page:?}");
	assert_eq!(fx.rows_on(member, &scope.topic).await, 2, "the rows stay, hidden");
}

/// An ordinary topic of a scope that also publishes a required one behaves as before: the
/// opt-out holds and the in-app switch hides it.
#[tokio::test]
async fn an_ordinary_topic_beside_a_required_one_keeps_the_member_s_choice() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let notice = format!("{}:notice", scope.id);
	let catalog = ScopeCatalog {
		version: 2,
		approval_kinds: Vec::new(),
		notification_topics: vec![news(&scope.topic, false, false), news(&notice, false, true)],
	};
	PgScopeCatalogs::new(fx.pool.clone()).publish(&scope.id, &scope.client, &catalog, now()).await.unwrap();
	let inbox = fx.inbox(&[&scope]);
	let (member, email) = fx.user("ordinary-member").await;
	fx.join(&scope, member).await;

	let quiet = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(!quiet.delivered, "never followed: {quiet:?}");
	fx.follow(member, &email, &scope.topic).await;
	let heard = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert_eq!((heard.delivered, heard.channels), (true, vec![1, 2]));
	assert!(inbox.emit_scope_notification(as_client(emit(member, &notice), &scope)).await.unwrap().into_inner().delivered);

	let sub = fx.notifications.subscriber_of_user(member).await.unwrap().unwrap();
	fx.notifications.set_channel_enabled(sub.id, Some(false), Some(false)).await.unwrap();
	let muted = inbox.emit_scope_notification(as_client(emit(member, &scope.topic), &scope)).await.unwrap().into_inner();
	assert!(!muted.delivered && !muted.notification_id.is_empty(), "written, delivered on no channel: {muted:?}");
	let page = inbox.list_scope_notifications(as_client(list(member), &scope)).await.unwrap().into_inner();
	assert_eq!(
		page.notifications.iter().map(|n| n.topic.as_str()).collect::<Vec<_>>(),
		vec![notice.as_str()],
		"with in-app off only the required notice shows"
	);
	let filtered = inbox
		.list_scope_notifications(as_client(
			ListScopeNotificationsRequest {
				topic: scope.topic.clone(),
				..list(member)
			},
			&scope,
		))
		.await
		.unwrap()
		.into_inner();
	assert!(filtered.notifications.is_empty(), "the ordinary topic stays hidden: {filtered:?}");
}
