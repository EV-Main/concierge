//! A scope's notification topics on `NotificationService` (`docs/SCOPES-AND-APPROVALS.md`
//! §6): the account-less subscribe takes a published one, and the keys that moved to a
//! scope keep working under their new names.
//!
//! Every test registers its own scope and catalog, so the suite runs beside the others on a
//! shared database.

use std::{sync::Arc, time::Duration};

mod common;

use concierge::{
	infrastructure::{db, notifications::PgNotifications, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	notification::{Notifications, RateLimiter, TOPICS},
	ports::{NotificationRepository, ScopeCatalogRepository, UserDirectoryRepository},
};
use domain::scope_catalog::{NotificationTopic, ScopeCatalog};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{
	EmitRequest, GetNotificationSettingsRequest, ListNotificationsRequest, SetTopicSubscriptionRequest, SubscribeAnonymousRequest, UnsubscribeRequest,
	notification_service_server::NotificationService,
};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

struct Fx {
	pool: PgPool,
	service: Notifications,
	notifications: Arc<PgNotifications>,
	users: Arc<PgUsers>,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let notifications = Arc::new(PgNotifications::new(pool.clone()));
	let users = Arc::new(PgUsers::new(pool.clone()));
	let service = Notifications::new(
		notifications.clone(),
		users.clone(),
		Arc::new(RateLimiter::new(Duration::from_secs(60), 1000)),
		std::sync::Arc::new(concierge::notice_link::NoticeLinkBases::cabinet_only("https://evinvest.ltd/cabinet")),
	);
	Some(Fx {
		pool,
		service,
		notifications,
		users,
	})
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn with_claims<T>(body: T, sub: &str, typ: TokenType) -> Request<T> {
	let mut request = Request::new(body);
	request.extensions_mut().insert(Claims {
		iss: "https://auth.concierge.test".into(),
		sub: sub.to_owned(),
		aud: "concierge-services".into(),
		exp: u64::MAX,
		iat: 0,
		typ,
		jti: None,
		token_version: 0,
		auth_time: None,
	});
	request
}

fn as_service<T>(body: T) -> Request<T> {
	with_claims(body, "edge", TokenType::Service)
}

fn as_user<T>(body: T, user: Uuid) -> Request<T> {
	with_claims(body, &user.to_string(), TokenType::Access)
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

fn subscribe(email: &str, topic: &str) -> SubscribeAnonymousRequest {
	SubscribeAnonymousRequest {
		email: email.to_owned(),
		topic: topic.to_owned(),
		client_ip: String::new(),
	}
}

impl Fx {
	/// A scope publishing one topic; its key.
	async fn scope(&self) -> String {
		let id = format!("t_{}", &Uuid::new_v4().simple().to_string()[..12]);
		sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, FALSE, 0)")
			.bind(&id)
			.execute(&self.pool)
			.await
			.expect("register the scope");
		let topic = format!("{id}:news");
		let catalog = ScopeCatalog {
			version: 1,
			approval_kinds: Vec::new(),
			notification_topics: vec![NotificationTopic {
				topic: topic.clone(),
				label: "News".into(),
				description: String::new(),
				default_subscribed: false,
				required: false,
				required_reason: String::new(),
			}],
		};
		PgScopeCatalogs::new(self.pool.clone()).publish(&id, "test", &catalog, now()).await.expect("publish");
		topic
	}

	async fn user(&self, tag: &str) -> (Uuid, String) {
		let user = self.users.resolve(common::google(tag, true), 0).await.unwrap();
		(user.id().raw(), user.email().as_str().to_owned())
	}

	/// The topics `user` has inbox rows on.
	async fn inbox_topics(&self, user: Uuid) -> Vec<String> {
		sqlx::query_scalar("SELECT n.topic FROM notifications n JOIN notification_subscribers s ON s.id = n.subscriber_id WHERE s.user_id = $1 ORDER BY n.created_at")
			.bind(user)
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}

	/// What `user` follows.
	async fn follows(&self, user: Uuid) -> Vec<String> {
		sqlx::query_scalar("SELECT t.topic FROM notification_subscriptions t JOIN notification_subscribers s ON s.id = t.subscriber_id WHERE s.user_id = $1 ORDER BY t.topic")
			.bind(user)
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}

	/// What the account-less subscriber of `email` follows.
	async fn followed(&self, email: &str) -> Vec<String> {
		sqlx::query_scalar(
			"SELECT t.topic FROM notification_subscriptions t JOIN notification_subscribers s ON s.id = t.subscriber_id \
			 WHERE s.user_id IS NULL AND lower(s.email) = lower($1) ORDER BY t.topic",
		)
		.bind(email)
		.fetch_all(&self.pool)
		.await
		.unwrap()
	}
}

/// An account-less address asks for a scope's topic as it asks for one of this plane's:
/// any topic a catalog in force publishes, double opt-in as ever.
#[tokio::test]
async fn an_address_subscribes_to_a_published_scope_topic() {
	let Some(fx) = setup().await else { return };
	let topic = fx.scope().await;
	let email = format!("anon-{}@example.com", Uuid::new_v4());

	let accepted = fx.service.subscribe_anonymous(as_service(subscribe(&email, &topic))).await.unwrap().into_inner();
	assert!(accepted.accepted);
	assert_eq!(fx.followed(&email).await, vec![topic.clone()]);

	let namespace = topic.split_once(':').unwrap().0;
	for unknown in [format!("{namespace}:unpublished"), "nope:nope".to_owned()] {
		let refused = fx.service.subscribe_anonymous(as_service(subscribe(&email, &unknown))).await.unwrap_err();
		assert_eq!(refused.code(), Code::InvalidArgument, "{unknown}");
	}
	assert_eq!(fx.followed(&email).await, vec![topic], "a refused topic is not followed");
}

/// `fund:quy-nhon` moved to `invest:` and `account:money-movement` to `bank:` (§6). Until the
/// emitters and pages have moved, the old key is accepted where a topic is named and stands
/// for the new one; `account:money-movement` itself stays this plane's trace topic.
#[tokio::test]
async fn a_moved_key_stands_for_its_new_one() {
	let Some(fx) = setup().await else { return };
	let (user, email) = fx.user("moved").await;

	let settings = fx
		.service
		.set_topic_subscription(as_user(
			SetTopicSubscriptionRequest {
				topic: "account:money-movement".into(),
				subscribed: true,
				email_enabled: true,
			},
			user,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(fx.follows(user).await, vec!["bank:money-movement".to_owned()], "following the old key follows the new one");
	assert!(
		settings.topics.iter().all(|t| t.topic != "account:money-movement" && t.topic != "fund:quy-nhon"),
		"neither old key is offered any more: {:?}",
		settings.topics
	);

	let sent = fx.service.emit(as_service(emit(user, "account:money-movement"))).await.unwrap().into_inner();
	assert!(sent.delivered, "{sent:?}");
	assert_eq!(
		fx.inbox_topics(user).await,
		vec!["bank:money-movement".to_owned()],
		"an emit on the old key lands under the new one"
	);

	// `invest:` reaches the invest scope's members only, whichever key named it.
	let sub = fx.notifications.subscriber_for_user(user, &email, true).await.unwrap();
	fx.notifications.set_topic_subscription(sub.id, "invest:fund:quy-nhon", true, true).await.unwrap();
	let outside = fx.service.emit(as_service(emit(user, "fund:quy-nhon"))).await.unwrap().into_inner();
	assert!(!outside.delivered, "not a member of invest yet: {outside:?}");
	sqlx::query("INSERT INTO scope_members (scope, user_id, joined_at, joined_by, lifecycle_sequence, sequence, permissions) VALUES ('invest', $1, 0, 'grant', 0, 1, '{}')")
		.bind(user)
		.execute(&fx.pool)
		.await
		.unwrap();
	let inside = fx.service.emit(as_service(emit(user, "fund:quy-nhon"))).await.unwrap().into_inner();
	assert!(inside.delivered, "{inside:?}");
	assert_eq!(fx.inbox_topics(user).await.last().map(String::as_str), Some("invest:fund:quy-nhon"));

	// The trace topic is still this plane's, written whatever anyone follows, shown in the
	// platform inbox and filterable there — and nobody follows it.
	assert!(
		fx.notifications
			.record(user, &email, true, "account:money-movement", "payment_consent", "t", "", &Uuid::new_v4().to_string(), now())
			.await
			.unwrap()
	);
	let traces = fx
		.service
		.list_notifications(as_user(
			ListNotificationsRequest {
				topic: "account:money-movement".into(),
				..Default::default()
			},
			user,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(traces.notifications.iter().map(|n| n.kind.as_str()).collect::<Vec<_>>(), vec!["payment_consent"]);
	let settings = fx.service.get_notification_settings(as_user(GetNotificationSettingsRequest {}, user)).await.unwrap().into_inner();
	let offered: Vec<_> = settings.topics.iter().map(|t| t.topic.as_str()).collect();
	for built_in in TOPICS {
		assert_eq!(offered.contains(&built_in.key), built_in.followable, "{}", built_in.key);
	}

	// The account-less path takes the old key too, and a one-click unsubscribe by it.
	let address = format!("anon-moved-{}@example.com", Uuid::new_v4());
	fx.service.subscribe_anonymous(as_service(subscribe(&address, "fund:quy-nhon"))).await.unwrap();
	assert_eq!(fx.followed(&address).await, vec!["invest:fund:quy-nhon".to_owned()]);
	let token: String = sqlx::query_scalar("SELECT unsubscribe_token FROM notification_subscribers WHERE user_id IS NULL AND lower(email) = lower($1)")
		.bind(&address)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let left = fx
		.service
		.unsubscribe(as_service(UnsubscribeRequest {
			token,
			topic: "fund:quy-nhon".into(),
		}))
		.await
		.unwrap()
		.into_inner();
	assert!(left.unsubscribed);
	assert!(fx.followed(&address).await.is_empty());
}

/// The migration that moves the keys, run over rows written under the old ones: every
/// subscription follows, a subscriber already on the new key keeps one row, the fund's
/// inbox history moves, and the money traces stay where this plane files them.
#[tokio::test]
async fn the_move_carries_subscriptions_and_history_across() {
	let Some(fx) = setup().await else { return };
	let (both, both_email) = fx.user("move-both").await;
	let (old_only, old_email) = fx.user("move-old").await;
	let both_sub = fx.notifications.subscriber_for_user(both, &both_email, true).await.unwrap().id;
	let old_sub = fx.notifications.subscriber_for_user(old_only, &old_email, true).await.unwrap().id;
	for (subscriber, topic, email_enabled) in [
		(both_sub, "fund:quy-nhon", false),
		(both_sub, "invest:fund:quy-nhon", true),
		(both_sub, "account:money-movement", true),
		(old_sub, "fund:quy-nhon", false),
		(old_sub, "account:money-movement", false),
	] {
		sqlx::query("INSERT INTO notification_subscriptions (subscriber_id, topic, email_enabled) VALUES ($1, $2, $3)")
			.bind(subscriber)
			.bind(topic)
			.bind(email_enabled)
			.execute(&fx.pool)
			.await
			.unwrap();
	}
	for (topic, kind) in [("fund:quy-nhon", "nav"), ("account:money-movement", "payment_consent")] {
		sqlx::query("INSERT INTO notifications (subscriber_id, topic, kind, title, dedupe_key, occurred_at) VALUES ($1, $2, $3, 't', $4, 0)")
			.bind(old_sub)
			.bind(topic)
			.bind(kind)
			.bind(Uuid::new_v4().to_string())
			.execute(&fx.pool)
			.await
			.unwrap();
	}

	let mut tx = fx.pool.begin().await.unwrap();
	sqlx::raw_sql(include_str!("../migrations/0042_move_scope_topics.up.sql")).execute(&mut *tx).await.unwrap();
	tx.commit().await.unwrap();

	let stance = |rows: Vec<concierge::infrastructure::notifications::SubscriptionRow>| rows.into_iter().map(|r| (r.topic, r.email_enabled)).collect::<Vec<_>>();
	assert_eq!(
		stance(fx.notifications.subscriptions(both_sub).await.unwrap()),
		vec![("bank:money-movement".to_owned(), true), ("invest:fund:quy-nhon".to_owned(), true)],
		"one row per new key; the one already there stands"
	);
	assert_eq!(
		stance(fx.notifications.subscriptions(old_sub).await.unwrap()),
		vec![("bank:money-movement".to_owned(), false), ("invest:fund:quy-nhon".to_owned(), false)],
		"the mail copy travels with the subscription"
	);
	assert_eq!(
		fx.inbox_topics(old_only).await,
		vec!["invest:fund:quy-nhon".to_owned(), "account:money-movement".to_owned()],
		"the fund's history moves; the money trace stays this plane's"
	);
}
