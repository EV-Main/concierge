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
	notification::{Notifications, RateLimiter},
	ports::ScopeCatalogRepository,
};
use domain::scope_catalog::{NotificationTopic, ScopeCatalog};
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{SubscribeAnonymousRequest, notification_service_server::NotificationService};
use sqlx::PgPool;
use tonic::{Code, Request};
use uuid::Uuid;

struct Fx {
	pool: PgPool,
	service: Notifications,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let service = Notifications::new(
		Arc::new(PgNotifications::new(pool.clone())),
		Arc::new(PgUsers::new(pool.clone())),
		Arc::new(RateLimiter::new(Duration::from_secs(60), 1000)),
	);
	Some(Fx { pool, service })
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn as_service<T>(body: T) -> Request<T> {
	let mut request = Request::new(body);
	request.extensions_mut().insert(Claims {
		iss: "https://auth.concierge.test".into(),
		sub: "edge".into(),
		aud: "concierge-services".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Service,
		jti: None,
		token_version: 0,
	});
	request
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
			}],
		};
		PgScopeCatalogs::new(self.pool.clone()).publish(&id, "test", &catalog, now()).await.expect("publish");
		topic
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
