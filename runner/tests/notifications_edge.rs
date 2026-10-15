//! The account-less notification edge on the web surface (`web::notifications`): the
//! subscribe form, and the confirm and unsubscribe links every topic mail carries.

mod common;

use std::sync::Mutex;

use async_trait::async_trait;
use axum::{
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::web::{Answer, Browser, INVEST, ORIGIN, Surface, address, surface};
use concierge::{
	dispatch::{DispatcherConfig, drain_once},
	infrastructure::{
		email::transport::{EmailTransport, OutgoingEmail},
		notifications::PgNotifications,
	},
	ports::NotificationRepository,
};
use domain::error::DomainError;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

const TOPIC: &str = "platform:announcements";

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

struct Page {
	status: StatusCode,
	headers: HeaderMap,
	html: String,
}

impl Page {
	fn hidden(&self, name: &str) -> Option<String> {
		let marker = format!("name=\"{name}\" value=\"");
		let start = self.html.find(&marker)? + marker.len();
		self.html[start..].split('"').next().map(str::to_owned)
	}
}

async fn send(fx: &Surface, method: Method, uri: &str, content_type: Option<&str>, body: &str) -> Page {
	let mut request = Request::builder().method(method).uri(uri);
	if let Some(content_type) = content_type {
		request = request.header(header::CONTENT_TYPE, content_type);
	}
	let response = fx.router.clone().oneshot(request.body(Body::from(body.to_owned())).unwrap()).await.unwrap();
	let (status, headers) = (response.status(), response.headers().clone());
	let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
	Page {
		status,
		headers,
		html: String::from_utf8(bytes.to_vec()).unwrap(),
	}
}

fn query(pairs: &[(&str, &str)]) -> String {
	let mut q = form_urlencoded::Serializer::new(String::new());
	for (k, v) in pairs {
		q.append_pair(k, v);
	}
	q.finish()
}

const FORM: Option<&str> = Some("application/x-www-form-urlencoded");

/// An account-less address with a confirmation mail queued: its subscriber id and the token
/// that mail carries.
async fn pending(fx: &Surface) -> (String, String) {
	let email = address("edge");
	let (_, token) = PgNotifications::new(fx.pool.clone())
		.subscribe_anonymous(&email, TOPIC, 3600)
		.await
		.expect("subscribe")
		.expect("a brand-new address is mailed a confirmation");
	(email, token)
}

async fn confirmed(fx: &Surface, email: &str) -> bool {
	sqlx::query_scalar("SELECT confirmed_at IS NOT NULL FROM notification_subscribers WHERE email = $1 AND user_id IS NULL")
		.bind(email)
		.fetch_one(&fx.pool)
		.await
		.unwrap()
}

/// A signed-in account's subscriber row following `TOPIC` with mail: its unsubscribe token.
async fn following(fx: &Surface) -> (Uuid, String) {
	let repo = PgNotifications::new(fx.pool.clone());
	let user = Uuid::new_v4();
	let sub = repo.subscriber_for_user(user, &address("unsub"), true).await.expect("subscriber");
	repo.set_topic_subscription(sub.id, TOPIC, true, true).await.expect("follow");
	(sub.id, sub.unsubscribe_token)
}

async fn mail_on(fx: &Surface, subscriber: Uuid) -> (bool, Option<bool>) {
	let channel: bool = sqlx::query_scalar("SELECT email_enabled FROM notification_subscribers WHERE id = $1")
		.bind(subscriber)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let topic: Option<bool> = sqlx::query_scalar("SELECT email_enabled FROM notification_subscriptions WHERE subscriber_id = $1 AND topic = $2")
		.bind(subscriber)
		.bind(TOPIC)
		.fetch_optional(&fx.pool)
		.await
		.unwrap();
	(channel, topic)
}

#[tokio::test]
async fn the_confirm_link_shows_a_button_and_only_the_button_confirms() {
	let fx = fixture!();
	let (email, token) = pending(&fx).await;

	let shown = send(&fx, Method::GET, &format!("/auth/notifications/confirm?{}", query(&[("token", &token)])), None, "").await;
	assert_eq!(shown.status, StatusCode::OK);
	assert_eq!(shown.hidden("token").as_deref(), Some(token.as_str()));
	assert!(shown.html.contains("action=\"/api/auth/notifications/confirm\""), "{}", shown.html);
	assert!(!shown.html.contains("<script") && !shown.html.contains("src="), "the page loads nothing");
	assert_eq!(shown.headers[header::CACHE_CONTROL], "no-store");
	assert_eq!(shown.headers[header::REFERRER_POLICY], "no-referrer");
	assert!(!confirmed(&fx, &email).await, "a scanner fetching the link confirms nothing");

	let pressed = send(&fx, Method::POST, "/auth/notifications/confirm", FORM, &query(&[("token", &token)])).await;
	assert_eq!(pressed.status, StatusCode::OK);
	assert!(pressed.html.contains("Subscription confirmed"), "{}", pressed.html);
	assert!(confirmed(&fx, &email).await);

	let again = send(&fx, Method::POST, "/auth/notifications/confirm", FORM, &query(&[("token", &token)])).await;
	let unknown = send(&fx, Method::POST, "/auth/notifications/confirm", FORM, &query(&[("token", "not-a-real-token")])).await;
	assert_eq!((again.status, unknown.status), (StatusCode::OK, StatusCode::OK));
	assert_eq!(again.html, unknown.html, "a spent token and one nobody holds read alike");
	assert!(!again.html.contains("Subscription confirmed"));
}

#[tokio::test]
async fn a_hostile_token_is_rendered_as_text() {
	let fx = fixture!();
	let hostile = "\"><script>alert(1)</script>";
	for path in ["/auth/notifications/confirm", "/auth/notifications/unsubscribe"] {
		let shown = send(&fx, Method::GET, &format!("{path}?{}", query(&[("token", hostile), ("topic", hostile)])), None, "").await;
		assert_eq!(shown.status, StatusCode::OK, "{path}");
		assert!(!shown.html.contains("<script"), "{path}: {}", shown.html);
	}
	let missing = send(&fx, Method::GET, "/auth/notifications/unsubscribe", None, "").await;
	assert_eq!(missing.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_unsubscribe_link_shows_a_button_and_changes_nothing() {
	let fx = fixture!();
	let (sub, token) = following(&fx).await;
	let shown = send(&fx, Method::GET, &format!("/auth/notifications/unsubscribe?{}", query(&[("token", &token)])), None, "").await;
	assert_eq!(shown.status, StatusCode::OK);
	assert_eq!(shown.hidden("token").as_deref(), Some(token.as_str()));
	assert_eq!(shown.hidden("topic"), None, "no topic named, none carried");
	assert!(shown.html.contains("action=\"/api/auth/notifications/unsubscribe\""), "{}", shown.html);
	assert_eq!(mail_on(&fx, sub).await, (true, Some(true)), "a scanner fetching the link unsubscribes nobody");
}

#[tokio::test]
async fn one_click_unsubscribes_with_a_200_and_no_redirect() {
	let fx = fixture!();
	let (sub, token) = following(&fx).await;
	let uri = format!("/auth/notifications/unsubscribe?{}", query(&[("token", &token)]));
	let clicked = send(&fx, Method::POST, &uri, FORM, "List-Unsubscribe=One-Click").await;
	assert_eq!(clicked.status, StatusCode::OK, "{}", clicked.html);
	assert!(clicked.headers.get(header::LOCATION).is_none());
	assert!(!mail_on(&fx, sub).await.0, "the email channel is off");

	// RFC 8058 lets the client send the marker as multipart; the token is in the query.
	let (sub, token) = following(&fx).await;
	let uri = format!("/auth/notifications/unsubscribe?{}", query(&[("token", &token)]));
	let multipart = "--b\r\nContent-Disposition: form-data; name=\"List-Unsubscribe\"\r\n\r\nOne-Click\r\n--b--\r\n";
	let clicked = send(&fx, Method::POST, &uri, Some("multipart/form-data; boundary=b"), multipart).await;
	assert_eq!(clicked.status, StatusCode::OK, "{}", clicked.html);
	assert!(!mail_on(&fx, sub).await.0);

	let unknown = send(&fx, Method::POST, "/auth/notifications/unsubscribe?token=not-a-real-token", FORM, "List-Unsubscribe=One-Click").await;
	assert_eq!((unknown.status, unknown.html), (StatusCode::OK, clicked.html), "a token nobody holds reads as one that worked");
}

#[tokio::test]
async fn the_button_unsubscribes_from_the_topic_it_names() {
	let fx = fixture!();
	let (sub, token) = following(&fx).await;
	let pressed = send(&fx, Method::POST, "/auth/notifications/unsubscribe", FORM, &query(&[("token", &token), ("topic", TOPIC)])).await;
	assert_eq!(pressed.status, StatusCode::OK, "{}", pressed.html);
	assert_eq!(mail_on(&fx, sub).await, (true, None), "the topic is left, the channel stays on");

	let (sub, token) = following(&fx).await;
	let unknown = send(
		&fx,
		Method::POST,
		"/auth/notifications/unsubscribe",
		FORM,
		&query(&[("token", &token), ("topic", "nope:nothing")]),
	)
	.await;
	assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
	assert_eq!(mail_on(&fx, sub).await, (true, Some(true)), "a refused topic changes nothing");
	let missing = send(&fx, Method::POST, "/auth/notifications/unsubscribe", FORM, "").await;
	assert_eq!(missing.status, StatusCode::BAD_REQUEST);
}

async fn queued_confirmations(fx: &Surface, email: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM notification_deliveries WHERE kind = 'confirm' AND recipient = $1")
		.bind(email)
		.fetch_one(&fx.pool)
		.await
		.unwrap()
}

async fn subscribe(fx: &Surface, origin: &str, email: &str, topic: &str, turnstile: &str) -> Answer {
	fx.post(
		"/auth/notifications/subscribe",
		origin,
		json!({ "email": email, "topic": topic, "turnstileToken": turnstile }),
		&mut Browser::default(),
	)
	.await
}

#[tokio::test]
async fn subscribing_takes_a_human_and_answers_alike() {
	let fx = fixture!();
	let email = address("subscribe");

	let robot = subscribe(&fx, ORIGIN, &email, TOPIC, "robot").await;
	assert_eq!((robot.status, robot.body), (StatusCode::FORBIDDEN, json!({ "error": "captcha" })));
	let foreign = subscribe(&fx, "https://evil.example", &email, TOPIC, "human").await;
	assert_eq!((foreign.status, foreign.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
	assert_eq!(queued_confirmations(&fx, &email).await, 0, "a refused request queues nothing");

	let first = subscribe(&fx, ORIGIN, &email, TOPIC, "human").await;
	assert_eq!((first.status, first.body), (StatusCode::OK, json!({ "accepted": true })));
	assert_eq!(queued_confirmations(&fx, &email).await, 1);
	let again = subscribe(&fx, INVEST, &email, TOPIC, "human").await;
	assert_eq!(again.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST, "a scope's page may read the answer");
	assert_eq!((again.status, again.body), (StatusCode::OK, json!({ "accepted": true })), "a throttled repeat answers the same");
	assert_eq!(queued_confirmations(&fx, &email).await, 1, "the database throttle held the second mail back");

	let bad = subscribe(&fx, ORIGIN, "not-an-address", TOPIC, "human").await;
	assert_eq!((bad.status, bad.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_email" })));
	let unknown = subscribe(&fx, ORIGIN, &address("unknown-topic"), "nope:nothing", "human").await;
	assert_eq!((unknown.status, unknown.body), (StatusCode::BAD_REQUEST, json!({ "error": "unknown_topic" })));
}

#[tokio::test]
async fn subscribing_spends_the_per_address_budget() {
	let fx = fixture!();
	// Every request here comes from the empty address, as no socket carries them.
	for _ in 0..common::SUBSCRIBES_PER_HOUR {
		assert_eq!(subscribe(&fx, ORIGIN, &address("budget"), TOPIC, "human").await.status, StatusCode::OK);
	}
	let over = subscribe(&fx, ORIGIN, &address("budget"), TOPIC, "human").await;
	assert_eq!((over.status, over.body), (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "throttled" })));
}

#[derive(Default)]
struct Outbox(Mutex<Vec<OutgoingEmail>>);

#[async_trait]
impl EmailTransport for Outbox {
	async fn send(&self, _from: &str, email: OutgoingEmail) -> Result<(), DomainError> {
		self.0.lock().unwrap().push(email);
		Ok(())
	}
}

#[tokio::test]
async fn the_mailed_links_lead_to_these_pages() {
	let fx = fixture!();
	let email = address("links");
	let asked = subscribe(&fx, ORIGIN, &email, TOPIC, "human").await;
	assert_eq!(asked.status, StatusCode::OK, "{:?}", asked.body);

	let outbox = Outbox::default();
	let cfg = DispatcherConfig {
		mail_from: "EV <noreply@evinvest.test>".into(),
		cabinet_url: format!("{ORIGIN}/cabinet"),
		public_origin: ORIGIN.into(),
		approvals_url: format!("{ORIGIN}/admin/approvals"),
		daily_budget: i64::MAX,
		interval: std::time::Duration::from_secs(60),
	};
	while drain_once(&PgNotifications::new(fx.pool.clone()), &outbox, &cfg).await > 0 {}
	let sent = outbox.0.lock().unwrap().iter().find(|m| m.to == email).cloned().expect("the confirmation was sent");

	let unsubscribe = format!("{ORIGIN}/api/auth/notifications/unsubscribe?token=");
	assert!(sent.unsubscribe_url.starts_with(&unsubscribe), "{}", sent.unsubscribe_url);
	let confirm = format!("{ORIGIN}/api/auth/notifications/confirm?token=");
	let link = sent.text.lines().find_map(|line| line.strip_prefix("Confirm: ")).expect("the text part carries the confirm link");
	assert!(link.starts_with(&confirm), "{link}");
	assert!(sent.html.contains(&confirm));

	// The link as the conductor hands it to this surface: `/api` stripped.
	let token = &link[confirm.len()..];
	let pressed = send(&fx, Method::POST, "/auth/notifications/confirm", FORM, &query(&[("token", token)])).await;
	assert!(pressed.html.contains("Subscription confirmed"), "{}", pressed.html);
	assert!(confirmed(&fx, &email).await);
}
