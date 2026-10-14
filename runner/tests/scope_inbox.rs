//! `ScopeInboxService` against a real Postgres: a direction's backend reads its users'
//! inbox with its client credential, and only its own namespace, only for its members.
//!
//! Every test makes its own scopes (tenant, client, secret, catalog) and its own users, so
//! the suite runs beside the others on a shared database.

use std::sync::Arc;

mod common;

use concierge::{
	infrastructure::{db, notifications::PgNotifications, relying_parties::PgRelyingParties, scope_catalogs::PgScopeCatalogs, users::PgUsers},
	notification::TOPICS,
	ports::{NotificationRepository, RelyingPartyRepository, ScopeCatalogRepository, UserDirectoryRepository},
	scope_inbox::ScopeInbox,
	service_caller::ServiceCallers,
};
use domain::scope_catalog::{NotificationTopic, ScopeCatalog};
use evconcierge_contracts::concierge::v1::{
	GetScopeNotificationSettingsRequest, GetScopeUnreadCountRequest, ListScopeNotificationsRequest, MarkScopeNotificationsReadRequest, SetScopeTopicSubscriptionRequest,
	scope_inbox_service_server::ScopeInboxService,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tonic::{Code, Request, metadata::MetadataValue};
use uuid::Uuid;

const BRIDGE_TOKEN: &str = "test-bridge-token";

struct Fx {
	pool: PgPool,
	inbox: ScopeInbox,
	notifications: Arc<PgNotifications>,
	users: Arc<PgUsers>,
}

struct Scope {
	id: String,
	client: String,
	secret: String,
	topic: String,
}

async fn setup() -> Option<Fx> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let callers = ServiceCallers::new(Some(BRIDGE_TOKEN.into()), Arc::new(PgRelyingParties::new(pool.clone())));
	let notifications = Arc::new(PgNotifications::new(pool.clone()));
	let users = Arc::new(PgUsers::new(pool.clone()));
	Some(Fx {
		inbox: ScopeInbox::new(callers, notifications.clone(), users.clone()),
		notifications,
		users,
		pool,
	})
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

impl Fx {
	/// A scope with one client, its secret and one published topic. `observers` name the
	/// clients that may read its stream.
	async fn scope(&self, observers: &[&Scope]) -> Scope {
		let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
		let scope = Scope {
			id: format!("x_{tag}"),
			client: format!("xc_{tag}"),
			secret: format!("{tag}{tag}{tag}"),
			topic: format!("x_{tag}:news"),
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
			.bind(vec![format!("https://{tag}.test/cb")])
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
			notification_topics: vec![NotificationTopic {
				topic: scope.topic.clone(),
				label: "News".into(),
				description: String::new(),
				default_subscribed: false,
			}],
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
		sqlx::query("INSERT INTO scope_members (scope, user_id, joined_at, joined_by, lifecycle_sequence, sequence, permissions) VALUES ($1, $2, 0, 'grant', 0, 1, '{}')")
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

fn with_client<T>(body: T, client: &str, secret: &str) -> Request<T> {
	let mut request = Request::new(body);
	request.metadata_mut().insert("x-ev-client-id", MetadataValue::try_from(client).unwrap());
	request.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {secret}")).unwrap());
	request
}

fn as_client<T>(body: T, scope: &Scope) -> Request<T> {
	with_client(body, &scope.client, &scope.secret)
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
	let (user, email) = fx.user("member").await;
	fx.join(&mine, user).await;
	fx.join(&other, user).await;
	for _ in 0..25 {
		fx.note(user, &email, &mine.topic).await;
	}
	fx.note(user, &email, &other.topic).await;
	fx.note(user, &email, TOPICS[2].key).await;
	fx.note(user, &email, "bank:anything").await;

	let page = fx.inbox.list_scope_notifications(as_client(list(user), &mine)).await.unwrap().into_inner();
	assert_eq!(page.notifications.len(), 20, "limit 0 is a real page, not one row");
	assert!(page.notifications.iter().all(|n| n.topic == mine.topic), "only this scope's namespace");
	assert!(!page.next_cursor.is_empty());
	assert_eq!(page.unread_count, 25);
	let rest = fx
		.inbox
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

	let unread = fx
		.inbox
		.get_scope_unread_count(as_client(GetScopeUnreadCountRequest { user_id: user.to_string() }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(unread.unread_count, 25);

	let settings = fx
		.inbox
		.get_scope_notification_settings(as_client(GetScopeNotificationSettingsRequest { user_id: user.to_string() }, &mine))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(settings.topics.iter().map(|t| t.topic.as_str()).collect::<Vec<_>>(), vec![mine.topic.as_str()]);
	assert_eq!(settings.email, email, "a member's own address, which the scope's stream already carries");

	let followed = fx
		.inbox
		.set_scope_topic_subscription(as_client(
			SetScopeTopicSubscriptionRequest {
				user_id: user.to_string(),
				topic: mine.topic.clone(),
				subscribed: true,
				email_enabled: false,
			},
			&mine,
		))
		.await
		.unwrap()
		.into_inner();
	assert!(followed.topics.iter().any(|t| t.topic == mine.topic && t.subscribed && !t.email_enabled));

	let all = fx
		.inbox
		.mark_scope_notifications_read(as_client(
			MarkScopeNotificationsReadRequest {
				user_id: user.to_string(),
				ids: Vec::new(),
				all: true,
			},
			&mine,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!((all.marked, all.unread_count), (25, 0));
	assert_eq!(fx.unread_rows(user).await, 3, "the other scope's, the built-in and the bank's stay unread");
}

#[tokio::test]
async fn a_non_member_reads_nothing_and_writes_nothing() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let (user, email) = fx.user("outsider").await;
	fx.note(user, &email, &scope.topic).await;

	let disabled = fx.user("disabled").await.0;
	fx.join(&scope, disabled).await;
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(disabled).execute(&fx.pool).await.unwrap();

	for id in [user, disabled, Uuid::new_v4()] {
		let page = fx.inbox.list_scope_notifications(as_client(list(id), &scope)).await.unwrap().into_inner();
		assert!(page.notifications.is_empty() && page.unread_count == 0, "{id}");
		let unread = fx
			.inbox
			.get_scope_unread_count(as_client(GetScopeUnreadCountRequest { user_id: id.to_string() }, &scope))
			.await
			.unwrap()
			.into_inner();
		assert_eq!(unread.unread_count, 0);
		let settings = fx
			.inbox
			.get_scope_notification_settings(as_client(GetScopeNotificationSettingsRequest { user_id: id.to_string() }, &scope))
			.await
			.unwrap()
			.into_inner();
		assert_eq!(settings, Default::default(), "not even whose address the id is: {id}");

		let mark = fx
			.inbox
			.mark_scope_notifications_read(as_client(
				MarkScopeNotificationsReadRequest {
					user_id: id.to_string(),
					ids: Vec::new(),
					all: true,
				},
				&scope,
			))
			.await
			.unwrap_err();
		assert_eq!(mark.code(), Code::FailedPrecondition);
		let follow = fx
			.inbox
			.set_scope_topic_subscription(as_client(
				SetScopeTopicSubscriptionRequest {
					user_id: id.to_string(),
					topic: scope.topic.clone(),
					subscribed: true,
					email_enabled: true,
				},
				&scope,
			))
			.await
			.unwrap_err();
		assert_eq!(follow.code(), Code::FailedPrecondition);
	}
	assert_eq!(fx.unread_rows(user).await, 1);
}

#[tokio::test]
async fn only_the_scope_s_own_client_opens_it() {
	let Some(fx) = setup().await else { return };
	let scope = fx.scope(&[]).await;
	let (user, _) = fx.user("creds").await;
	fx.join(&scope, user).await;

	let wrong = fx.inbox.list_scope_notifications(with_client(list(user), &scope.client, "not-the-secret")).await.unwrap_err();
	assert_eq!(wrong.code(), Code::Unauthenticated);
	let unknown = fx.inbox.list_scope_notifications(with_client(list(user), "nobody_here", &scope.secret)).await.unwrap_err();
	assert_eq!(unknown.code(), Code::Unauthenticated);
	let anonymous = fx.inbox.list_scope_notifications(Request::new(list(user))).await.unwrap_err();
	assert_eq!(anonymous.code(), Code::Unauthenticated);

	let mut bridge = Request::new(list(user));
	bridge.metadata_mut().insert("authorization", MetadataValue::try_from(format!("Bearer {BRIDGE_TOKEN}")).unwrap());
	assert_eq!(fx.inbox.list_scope_notifications(bridge).await.unwrap_err().code(), Code::PermissionDenied);

	sqlx::query("UPDATE rp_clients SET disabled_at = 0 WHERE client_id = $1")
		.bind(&scope.client)
		.execute(&fx.pool)
		.await
		.unwrap();
	let disabled = fx.inbox.list_scope_notifications(as_client(list(user), &scope)).await.unwrap_err();
	assert_eq!(disabled.code(), Code::Unauthenticated);

	let closed = fx.scope(&[]).await;
	fx.join(&closed, user).await;
	sqlx::query("UPDATE tenants SET state = 'closed' WHERE id = $1").bind(&closed.id).execute(&fx.pool).await.unwrap();
	let refused = fx.inbox.list_scope_notifications(as_client(list(user), &closed)).await.unwrap_err();
	assert_eq!(refused.code(), Code::FailedPrecondition);
}

/// An observer reads a scope's stream, never its users' inbox: the namespace is always the
/// caller's own.
#[tokio::test]
async fn a_client_never_reaches_another_scope_s_inbox_even_as_its_observer() {
	let Some(fx) = setup().await else { return };
	let a = fx.scope(&[]).await;
	let b = fx.scope(&[&a]).await;
	let (user, email) = fx.user("both").await;
	fx.join(&a, user).await;
	fx.join(&b, user).await;
	let of_b = fx.note(user, &email, &b.topic).await;

	let page = fx.inbox.list_scope_notifications(as_client(list(user), &a)).await.unwrap().into_inner();
	assert!(page.notifications.is_empty(), "{:?}", page.notifications);
	let filter = fx
		.inbox
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

	let marked = fx
		.inbox
		.mark_scope_notifications_read(as_client(
			MarkScopeNotificationsReadRequest {
				user_id: user.to_string(),
				ids: vec![of_b.to_string()],
				all: false,
			},
			&a,
		))
		.await
		.unwrap()
		.into_inner();
	assert_eq!(marked.marked, 0, "another inbox's id is not marked");
	assert_eq!(fx.unread_rows(user).await, 1);

	let follow = fx
		.inbox
		.set_scope_topic_subscription(as_client(
			SetScopeTopicSubscriptionRequest {
				user_id: user.to_string(),
				topic: b.topic.clone(),
				subscribed: true,
				email_enabled: true,
			},
			&a,
		))
		.await
		.unwrap_err();
	assert_eq!(follow.code(), Code::InvalidArgument);

	let own = fx.inbox.list_scope_notifications(as_client(list(user), &b)).await.unwrap().into_inner();
	assert_eq!(own.notifications.iter().map(|n| n.id.clone()).collect::<Vec<_>>(), vec![of_b.to_string()]);
}
