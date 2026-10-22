//! Each direction's inbox is its own (D21): the server decides which namespace a request
//! reads from where it came from — the `Origin` on the web surface, the token on gRPC —
//! and a scope's inbox is shown only to the scope's members. The summary of every
//! namespace is `PUBLIC_ORIGIN` only and behind `concierge:notifications:read_all`.
//!
//! The scopes here are made per test (a tenant row with its own origin and catalog) rather
//! than the seeded `invest`/`sa`, whose catalogs other suites on a shared database publish.

use std::sync::Arc;

mod common;

use axum::http::{Method, StatusCode};
use common::web::{Browser, ORIGIN, Surface, address, surface};
use concierge::{
	infrastructure::{notifications::PgNotifications, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	notification::{INBOX_VIEW_HEADER, MAX_MARK_IDS, Notifications, RateLimiter, TOPICS},
	ports::{NotificationRepository, ScopeCatalogRepository, UserDirectoryRepository},
};
use domain::scope_catalog::{NotificationTopic, ScopeCatalog};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	GetNotificationSettingsRequest, GetUnreadCountRequest, ListNotificationsRequest, MarkReadRequest, SetTopicSubscriptionRequest, notification_service_server::NotificationService,
};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use tonic::{Code, Request};
use uuid::Uuid;

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

/// The key `governance.rs` and `authz_gate.rs` serialize on: both clear the owner roster,
/// and the summary is checked here with an owner.
const ROSTER_LOCK: i64 = 0x676f_765f_6974;

struct Scope {
	id: String,
	origin: String,
	topic: String,
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A scope with one host and one published topic. Registered BEFORE the surface is built:
/// the allowlist reads the registry once at construction.
async fn scope(pool: &PgPool) -> Scope {
	scope_with(pool, false).await
}

const REASON: &str = "Holders are told before new fee terms bind";

/// [`scope`], its topic `required` or not.
async fn scope_with(pool: &PgPool, required: bool) -> Scope {
	let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
	let scope = Scope {
		id: format!("i_{tag}"),
		origin: format!("https://i{tag}.evinvest.ltd"),
		topic: format!("i_{tag}:news"),
	};
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, origins, return_paths) VALUES ($1, $1, FALSE, 0, $2, ARRAY['/'])")
		.bind(&scope.id)
		.bind(vec![scope.origin.clone()])
		.execute(pool)
		.await
		.expect("register the scope");
	let catalog = ScopeCatalog {
		version: 1,
		approval_kinds: Vec::new(),
		notification_topics: vec![NotificationTopic {
			topic: scope.topic.clone(),
			label: "News".into(),
			description: String::new(),
			default_subscribed: false,
			required,
			required_reason: if required { REASON.into() } else { String::new() },
		}],
	};
	PgScopeCatalogs::new(pool.clone())
		.publish(&scope.id, "test", &catalog, now())
		.await
		.expect("publish the scope's catalog");
	scope
}

/// The required `bank:` topic [`bank_topic`] publishes beside the ordinary one.
const BANK_NOTICE: &str = "bank:notice_test";

/// A `bank:` topic in the money plane's catalog, and the required [`BANK_NOTICE`] beside it.
/// The catalog is shared with every suite on the database, and `scope_inbox.rs` leaves it a
/// second ahead of the clock just before this binary runs, so the topics are added to the
/// catalog in force under a version past both, as that suite does; a race between the tests
/// here ends in the same content.
async fn bank_topic(pool: &PgPool) -> String {
	const TOPIC: &str = "bank:inbox_test";
	let mine = [
		NotificationTopic {
			topic: TOPIC.into(),
			label: "Money".into(),
			description: String::new(),
			default_subscribed: false,
			required: false,
			required_reason: String::new(),
		},
		NotificationTopic {
			topic: BANK_NOTICE.into(),
			label: "Money notices".into(),
			description: String::new(),
			default_subscribed: false,
			required: true,
			required_reason: REASON.into(),
		},
	];
	let catalogs = PgScopeCatalogs::new(pool.clone());
	for _ in 0..10 {
		let current = catalogs.current("bank").await.unwrap();
		if current.as_ref().is_some_and(|c| mine.iter().all(|t| c.notification_topics.contains(t))) {
			return TOPIC.into();
		}
		let mut catalog = current.unwrap_or(ScopeCatalog {
			version: 0,
			approval_kinds: Vec::new(),
			notification_topics: Vec::new(),
		});
		catalog.notification_topics.retain(|t| mine.iter().all(|m| m.topic != t.topic));
		catalog.notification_topics.extend(mine.iter().cloned());
		catalog.version = catalog.version.max(now() as u64) + 1;
		catalogs.publish("bank", "bridge", &catalog, now()).await.expect("publish the bank catalog");
	}
	panic!("the bank catalog never held this suite's topics");
}

async fn join(pool: &PgPool, scope: &Scope, user: Uuid) {
	sqlx::query("INSERT INTO scope_members (scope, user_id, joined_at, joined_by, lifecycle_sequence, sequence, permissions) VALUES ($1, $2, 0, 'grant', 0, 1, '{}')")
		.bind(&scope.id)
		.bind(user)
		.execute(pool)
		.await
		.expect("make the user a member");
}

async fn signed_in(fx: &Surface, tag: &str) -> (Browser, Uuid) {
	let mut browser = Browser::default();
	let done = fx.sign_in_with_code(&address(tag), &mut browser).await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	let id = Uuid::parse_str(fx.get("/auth/me", &mut browser).await.body["id"].as_str().unwrap()).unwrap();
	(browser, id)
}

fn topics(body: &Value) -> Vec<String> {
	body["topics"].as_array().expect("a topic list").iter().map(|t| t["topic"].as_str().unwrap().to_owned()).collect()
}

async fn settings_from(fx: &Surface, origin: &str, query: &str, browser: &mut Browser) -> (StatusCode, Value) {
	let answer = fx.send(Method::GET, &format!("/auth/notifications/settings{query}"), origin, None, browser, false).await;
	(answer.status, answer.body)
}

#[tokio::test]
async fn a_scope_member_sees_only_the_scope_namespace_on_its_host() {
	let Some(url) = common::database_url() else { return };
	let pool = PgPool::connect(&url).await.unwrap();
	let mine = scope(&pool).await;
	let other = scope(&pool).await;
	let fx = fixture!();
	let (mut browser, id) = signed_in(&fx, "member").await;
	join(&fx.pool, &mine, id).await;

	let (status, body) = settings_from(&fx, &mine.origin, "", &mut browser).await;
	assert_eq!(status, StatusCode::OK, "{body:?}");
	assert_eq!(topics(&body), vec![mine.topic.clone()], "only the scope's own namespace, no built-in and no other scope");
	assert_eq!(body["email_verified"], true, "the rest of the snapshot is the account's");

	let followed = fx
		.post(
			"/auth/notifications/settings/topic",
			&mine.origin,
			json!({ "topic": mine.topic, "subscribed": true, "email_enabled": false }),
			&mut browser,
		)
		.await;
	assert_eq!(followed.status, StatusCode::OK, "{:?}", followed.body);
	assert_eq!(topics(&followed.body), vec![mine.topic.clone()], "the answer is the same inbox");

	for foreign in [other.topic.as_str(), TOPICS[0].key] {
		let refused = fx
			.post(
				"/auth/notifications/settings/topic",
				&mine.origin,
				json!({ "topic": foreign, "subscribed": true, "email_enabled": true }),
				&mut browser,
			)
			.await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "unknown_topic" })), "{foreign}");
	}

	// A master switch is every inbox's at once, so it is set where every inbox is seen.
	let channel = fx
		.post(
			"/auth/notifications/settings/channel",
			&mine.origin,
			json!({ "channel": "email", "enabled": false }),
			&mut browser,
		)
		.await;
	assert_eq!((channel.status, channel.body), (StatusCode::FORBIDDEN, json!({ "error": "platform_only" })));
}

#[tokio::test]
async fn a_scope_host_shows_an_outsider_nothing_and_lets_them_follow_nothing() {
	let Some(url) = common::database_url() else { return };
	let pool = PgPool::connect(&url).await.unwrap();
	let theirs = scope(&pool).await;
	let fx = fixture!();
	let (mut browser, _) = signed_in(&fx, "outsider").await;

	let (status, body) = settings_from(&fx, &theirs.origin, "", &mut browser).await;
	assert_eq!(status, StatusCode::OK, "an outsider is not refused: {body:?}");
	assert!(topics(&body).is_empty(), "an empty inbox: {body:?}");

	let refused = fx
		.post(
			"/auth/notifications/settings/topic",
			&theirs.origin,
			json!({ "topic": theirs.topic, "subscribed": true, "email_enabled": true }),
			&mut browser,
		)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "unknown_topic" })));
}

#[tokio::test]
async fn the_platform_inbox_holds_the_built_ins_and_the_bank_and_no_scope() {
	let Some(url) = common::database_url() else { return };
	let pool = PgPool::connect(&url).await.unwrap();
	let a_scope = scope(&pool).await;
	let bank = bank_topic(&pool).await;
	let fx = fixture!();
	let (mut browser, id) = signed_in(&fx, "platform").await;
	join(&fx.pool, &a_scope, id).await;

	for origin in [Some(ORIGIN), None] {
		let mut request = axum::http::Request::builder().method(Method::GET).uri("/auth/notifications/settings");
		if let Some(origin) = origin {
			request = request.header(axum::http::header::ORIGIN, origin);
		}
		let request = request.header(axum::http::header::COOKIE, browser.header()).body(axum::body::Body::empty()).unwrap();
		let response = tower::ServiceExt::oneshot(fx.router.clone(), request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK, "{origin:?}");
		let body: Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
		let shown = topics(&body);
		for t in TOPICS {
			assert_eq!(shown.iter().any(|s| s == t.key), t.followable, "{origin:?}: built-in {} is offered iff followable", t.key);
		}
		assert!(shown.contains(&bank), "{origin:?}: the money plane's topics are everyone's");
		assert!(
			shown.iter().all(|s| TOPICS.iter().any(|t| t.key == s) || s.starts_with("bank:")),
			"{origin:?}: no scope's topic, even for its member: {shown:?}"
		);
	}

	let refused = fx
		.post(
			"/auth/notifications/settings/topic",
			ORIGIN,
			json!({ "topic": a_scope.topic, "subscribed": true, "email_enabled": true }),
			&mut browser,
		)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "unknown_topic" })));

	let (status, body) = settings_from(&fx, "https://evil.example", "", &mut browser).await;
	assert_eq!(
		(status, body),
		(StatusCode::FORBIDDEN, json!({ "error": "origin_not_allowed" })),
		"an origin nobody registered reads no inbox"
	);
}

#[tokio::test]
async fn the_summary_needs_the_permission_and_the_public_origin() {
	let Some(url) = common::database_url() else { return };
	common::assert_disposable_database();
	let pool = PgPool::connect(&url).await.unwrap();
	let a_scope = scope(&pool).await;
	let fx = fixture!();
	let (mut browser, id) = signed_in(&fx, "summary").await;

	let (status, body) = settings_from(&fx, ORIGIN, "?all=1", &mut browser).await;
	assert_eq!((status, body), (StatusCode::FORBIDDEN, json!({ "error": "forbidden" })), "an investor has no summary");

	let mut roster_lock = PgConnection::connect(&url).await.unwrap();
	sqlx::query("SELECT pg_advisory_lock($1)").bind(ROSTER_LOCK).execute(&mut roster_lock).await.unwrap();
	sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1").bind(id).execute(&fx.pool).await.unwrap();

	let (status, body) = settings_from(&fx, ORIGIN, "?all=1", &mut browser).await;
	let (on_scope_host, _) = settings_from(&fx, &a_scope.origin, "?all=1", &mut browser).await;

	sqlx::query("UPDATE users SET role = 'investor' WHERE id = $1").bind(id).execute(&fx.pool).await.unwrap();
	sqlx::query("SELECT pg_advisory_unlock($1)").bind(ROSTER_LOCK).execute(&mut roster_lock).await.unwrap();

	assert_eq!(status, StatusCode::OK, "{body:?}");
	let shown = topics(&body);
	assert!(shown.contains(&a_scope.topic), "every namespace, without being a member: {shown:?}");
	assert!(shown.iter().any(|s| s == TOPICS[0].key), "the built-ins too");
	assert_eq!(on_scope_host, StatusCode::FORBIDDEN, "the summary is never served to a scope's host");

	for query in ["?all=yes", "?all=1&all=1"] {
		let answer = settings_from(&fx, ORIGIN, query, &mut browser).await;
		assert_eq!(answer, (StatusCode::BAD_REQUEST, json!({ "error": "invalid_view" })), "{query}");
	}
}

fn as_user(id: Uuid) -> Claims {
	Claims {
		iss: "https://auth.concierge.ev".into(),
		sub: id.to_string(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
		auth_time: None,
	}
}

fn grpc<T>(id: Uuid, inner: T, summary: bool) -> Request<T> {
	let mut request = Request::new(inner);
	request.extensions_mut().insert(as_user(id));
	if summary {
		request.metadata_mut().insert(INBOX_VIEW_HEADER, "all".parse().unwrap());
	}
	request
}

/// A user's token on gRPC reads the platform inbox: the list, the count, mark-all and the
/// settings leave every scope's notifications alone.
#[tokio::test]
async fn a_user_token_on_grpc_reads_the_platform_inbox() {
	let Some(url) = common::database_url() else { return };
	common::assert_disposable_database();
	let pool = concierge::infrastructure::db::connect_sized(&url, 5).await.unwrap();
	concierge::infrastructure::db::migrate(&pool).await.unwrap();
	let a_scope = scope(&pool).await;
	let bank = bank_topic(&pool).await;
	let users = Arc::new(PgUsers::new(pool.clone()));
	let repo = Arc::new(PgNotifications::new(pool.clone()));
	let service = Notifications::new(
		repo.clone(),
		users.clone(),
		Arc::new(RateLimiter::new(std::time::Duration::from_secs(60), 10)),
		std::sync::Arc::new(concierge::notice_link::NoticeLinkBases::cabinet_only("https://evinvest.ltd/cabinet")),
	);
	let user = users.resolve(common::google("grpc", true), 0).await.unwrap();
	let id = user.id().raw();
	join(&pool, &a_scope, id).await;
	for (i, topic) in [TOPICS[2].key, bank.as_str(), a_scope.topic.as_str()].into_iter().enumerate() {
		assert!(
			repo.record(id, user.email().as_str(), true, topic, "k", &format!("t{i}"), "", &format!("d{i}"), 100 + i as i64)
				.await
				.unwrap()
		);
	}

	let listed = service.list_notifications(grpc(id, ListNotificationsRequest::default(), false)).await.unwrap().into_inner();
	let mut seen: Vec<_> = listed.notifications.iter().map(|n| n.topic.clone()).collect();
	seen.sort();
	let mut platform = vec![TOPICS[2].key.to_owned(), bank.clone()];
	platform.sort();
	assert_eq!(seen, platform, "no scope's notification in the platform inbox");
	assert_eq!(listed.unread_count, 2);
	assert_eq!(service.get_unread_count(grpc(id, GetUnreadCountRequest {}, false)).await.unwrap().into_inner().unread_count, 2);
	let filtered = service
		.list_notifications(grpc(
			id,
			ListNotificationsRequest {
				topic: a_scope.topic.clone(),
				..Default::default()
			},
			false,
		))
		.await
		.unwrap_err();
	assert_eq!(filtered.code(), Code::InvalidArgument, "a scope's topic is no filter here");

	let settings = service.get_notification_settings(grpc(id, GetNotificationSettingsRequest {}, false)).await.unwrap().into_inner();
	assert!(settings.topics.iter().all(|t| t.topic != a_scope.topic), "nor in the settings");
	let follow = service
		.set_topic_subscription(grpc(
			id,
			SetTopicSubscriptionRequest {
				topic: a_scope.topic.clone(),
				subscribed: true,
				email_enabled: true,
			},
			false,
		))
		.await
		.unwrap_err();
	assert_eq!(follow.code(), Code::InvalidArgument);

	let marked = service.mark_read(grpc(id, MarkReadRequest { ids: Vec::new(), all: true }, false)).await.unwrap().into_inner();
	assert_eq!((marked.marked, marked.unread_count), (2, 0), "mark-all marks the platform inbox only");
	let scope_unread: i64 = sqlx::query_scalar("SELECT count(*) FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 AND n.read_at IS NULL")
		.bind(id)
		.fetch_one(&pool)
		.await
		.unwrap();
	assert_eq!(scope_unread, 1, "the scope's notification is still unread");

	let denied = service.list_notifications(grpc(id, ListNotificationsRequest::default(), true)).await.unwrap_err();
	assert_eq!(denied.code(), Code::PermissionDenied, "an investor has no summary");
	// The one subject break-glass could elevate is one with no persisted seat at all.
	let seatless = service.list_notifications(grpc(Uuid::new_v4(), ListNotificationsRequest::default(), true)).await.unwrap_err();
	assert_eq!(seatless.code(), Code::PermissionDenied, "the summary reads the persisted seat only");

	let too_many = MarkReadRequest {
		ids: (0..=MAX_MARK_IDS).map(|_| Uuid::new_v4().to_string()).collect(),
		all: false,
	};
	assert_eq!(service.mark_read(grpc(id, too_many, false)).await.unwrap_err().code(), Code::InvalidArgument);

	let mut roster_lock = PgConnection::connect(&url).await.unwrap();
	sqlx::query("SELECT pg_advisory_lock($1)").bind(ROSTER_LOCK).execute(&mut roster_lock).await.unwrap();
	sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1").bind(id).execute(&pool).await.unwrap();
	let summary = service.list_notifications(grpc(id, ListNotificationsRequest::default(), true)).await;
	sqlx::query("UPDATE users SET role = 'investor' WHERE id = $1").bind(id).execute(&pool).await.unwrap();
	sqlx::query("SELECT pg_advisory_unlock($1)").bind(ROSTER_LOCK).execute(&mut roster_lock).await.unwrap();

	let summary = summary.unwrap().into_inner();
	assert_eq!(summary.notifications.len(), 3, "an owner's summary holds every namespace");
	assert_eq!(summary.unread_count, 1);
}

/// Every door that switches a topic refuses to switch a required one off: the web settings
/// route on a scope's host (`409 required_topic`) and `SetTopicSubscription` on the
/// platform inbox (`FAILED_PRECONDITION`). Both show it as on and locked, with the reason,
/// and both accept following it.
#[tokio::test]
async fn a_required_topic_is_locked_on_the_web_and_on_grpc() {
	let Some(url) = common::database_url() else { return };
	let pool = PgPool::connect(&url).await.unwrap();
	let mine = scope_with(&pool, true).await;
	bank_topic(&pool).await;
	let fx = fixture!();
	let (mut browser, id) = signed_in(&fx, "required").await;
	join(&fx.pool, &mine, id).await;

	let (status, body) = settings_from(&fx, &mine.origin, "", &mut browser).await;
	assert_eq!(status, StatusCode::OK, "{body:?}");
	let shown = &body["topics"][0];
	assert_eq!(
		(&shown["topic"], &shown["subscribed"], &shown["email_enabled"], &shown["required"], &shown["required_reason"]),
		(&json!(mine.topic), &json!(true), &json!(true), &json!(true), &json!(REASON))
	);
	for (subscribed, email_enabled) in [(false, false), (true, false)] {
		let refused = fx
			.post(
				"/auth/notifications/settings/topic",
				&mine.origin,
				json!({ "topic": mine.topic, "subscribed": subscribed, "email_enabled": email_enabled }),
				&mut browser,
			)
			.await;
		assert_eq!(
			(refused.status, refused.body),
			(StatusCode::CONFLICT, json!({ "error": "required_topic" })),
			"{subscribed}/{email_enabled}"
		);
	}
	let followed = fx
		.post(
			"/auth/notifications/settings/topic",
			&mine.origin,
			json!({ "topic": mine.topic, "subscribed": true, "email_enabled": true }),
			&mut browser,
		)
		.await;
	assert_eq!(followed.status, StatusCode::OK, "following a required topic is accepted: {:?}", followed.body);

	let service = Notifications::new(
		Arc::new(PgNotifications::new(fx.pool.clone())),
		Arc::new(PgUsers::new(fx.pool.clone())),
		Arc::new(RateLimiter::new(std::time::Duration::from_secs(60), 10)),
		Arc::new(concierge::notice_link::NoticeLinkBases::cabinet_only("https://evinvest.ltd/cabinet")),
	);
	let change = |subscribed: bool| SetTopicSubscriptionRequest {
		topic: BANK_NOTICE.into(),
		subscribed,
		email_enabled: subscribed,
	};
	let refused = service.set_topic_subscription(grpc(id, change(false), false)).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition, "{refused:?}");
	assert!(refused.message().starts_with("required_topic:"), "{refused:?}");
	let settings = service.set_topic_subscription(grpc(id, change(true), false)).await.unwrap().into_inner();
	let notice = settings.topics.iter().find(|t| t.topic == BANK_NOTICE).expect("the platform inbox offers it");
	assert!(notice.required && notice.subscribed && notice.email_enabled && notice.required_reason == REASON, "{notice:?}");
	let ordinary = settings.topics.iter().find(|t| t.topic == "bank:inbox_test").expect("and the ordinary one");
	assert!(!ordinary.required && ordinary.required_reason.is_empty(), "{ordinary:?}");
}
