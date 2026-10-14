//! The account MFE's routes on the web surface: `GET /auth/me` and the notification
//! settings, read and written.

mod common;

use axum::http::{Method, StatusCode, header};
use common::web::{Browser, INVEST, ORIGIN, Surface, address, surface};
use concierge::notification::TOPICS;
use serde_json::json;

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

async fn signed_in(fx: &Surface, email: &str) -> Browser {
	let mut browser = Browser::default();
	let done = fx.sign_in_with_code(email, &mut browser).await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	browser
}

#[tokio::test]
async fn me_answers_the_account_without_its_documents() {
	let fx = fixture!();
	let anonymous = fx.get("/auth/me", &mut Browser::default()).await;
	assert_eq!((anonymous.status, anonymous.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));

	let email = address("me");
	let mut browser = signed_in(&fx, &email).await;
	let me = fx.get("/auth/me", &mut browser).await;
	assert_eq!(me.status, StatusCode::OK);
	assert_eq!(me.headers[header::CACHE_CONTROL], "no-store");
	let body = me.body.as_object().unwrap();
	let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
	keys.sort_unstable();
	assert_eq!(keys, ["email", "email_verified", "id", "kyc_level", "preferred_name", "role", "role_is_break_glass", "username"]);
	assert_eq!(body["email"], email.as_str());
	assert_eq!(body["email_verified"], true);
	assert_eq!(body["role"], "investor");
	assert_eq!(body["kyc_level"], 0);
}

#[tokio::test]
async fn settings_read_every_topic_with_the_callers_choice() {
	let fx = fixture!();
	let email = address("settings");
	let mut browser = signed_in(&fx, &email).await;
	let read = fx.get("/auth/notifications/settings", &mut browser).await;
	assert_eq!(read.status, StatusCode::OK);
	assert_eq!(read.headers[header::CACHE_CONTROL], "no-store");
	assert_eq!(read.body["email"], email.as_str());
	assert_eq!(read.body["email_verified"], true);
	assert_eq!(read.body["in_app_enabled"], true);
	let topics = read.body["topics"].as_array().unwrap();
	assert_eq!(
		topics.iter().map(|t| t["topic"].as_str().unwrap()).collect::<Vec<_>>(),
		TOPICS.iter().map(|t| t.key).collect::<Vec<_>>()
	);
	let first = topics[0].as_object().unwrap();
	let mut keys: Vec<&str> = first.keys().map(String::as_str).collect();
	keys.sort_unstable();
	assert_eq!(keys, ["description", "email_enabled", "label", "subscribed", "topic"]);

	let anonymous = fx.get("/auth/notifications/settings", &mut Browser::default()).await;
	assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_channel_and_a_topic_are_set_and_answered_whole() {
	let fx = fixture!();
	let mut browser = signed_in(&fx, &address("write")).await;

	let channel = fx
		.post("/auth/notifications/settings/channel", ORIGIN, json!({ "channel": "in_app", "enabled": false }), &mut browser)
		.await;
	assert_eq!(channel.status, StatusCode::OK, "{:?}", channel.body);
	assert_eq!(channel.body["in_app_enabled"], false);
	assert_eq!(channel.body["email_enabled"], true);
	assert!(channel.body["topics"].as_array().is_some_and(|t| t.len() == TOPICS.len()), "the whole snapshot");

	let key = TOPICS[0].key;
	let topic = fx
		.post(
			"/auth/notifications/settings/topic",
			ORIGIN,
			json!({ "topic": key, "subscribed": true, "email_enabled": false }),
			&mut browser,
		)
		.await;
	assert_eq!(topic.status, StatusCode::OK, "{:?}", topic.body);
	let row = topic.body["topics"].as_array().unwrap().iter().find(|t| t["topic"] == key).unwrap().clone();
	assert_eq!((row["subscribed"].clone(), row["email_enabled"].clone()), (json!(true), json!(false)));
	assert_eq!(topic.body["in_app_enabled"], false, "the channel choice stays");

	let reread = fx.get("/auth/notifications/settings", &mut browser).await;
	assert_eq!(reread.body, topic.body, "what was answered is what is stored");

	let unknown = fx
		.post(
			"/auth/notifications/settings/topic",
			ORIGIN,
			json!({ "topic": "nope:nope", "subscribed": true, "email_enabled": true }),
			&mut browser,
		)
		.await;
	assert_eq!((unknown.status, unknown.body), (StatusCode::BAD_REQUEST, json!({ "error": "unknown_topic" })));
	let channel = fx
		.post("/auth/notifications/settings/channel", ORIGIN, json!({ "channel": "sms", "enabled": true }), &mut browser)
		.await;
	assert_eq!((channel.status, channel.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_channel" })));
}

#[tokio::test]
async fn a_write_needs_the_csrf_token_and_answers_no_scope_host() {
	let fx = fixture!();
	let mut browser = signed_in(&fx, &address("csrf")).await;
	let forged = fx
		.send(
			Method::POST,
			"/auth/notifications/settings/channel",
			ORIGIN,
			Some(json!({ "channel": "email", "enabled": false })),
			&mut browser,
			false,
		)
		.await;
	assert_eq!((forged.status, forged.body), (StatusCode::FORBIDDEN, json!({ "error": "csrf" })));

	let anonymous = fx
		.post(
			"/auth/notifications/settings/channel",
			ORIGIN,
			json!({ "channel": "email", "enabled": false }),
			&mut Browser::default(),
		)
		.await;
	assert_eq!((anonymous.status, anonymous.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));

	for path in [
		"/auth/me",
		"/auth/notifications/settings",
		"/auth/notifications/settings/channel",
		"/auth/notifications/settings/topic",
	] {
		let answer = fx.send(Method::OPTIONS, path, INVEST, None, &mut Browser::default(), false).await;
		assert!(!answer.headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{path}");
		let answer = fx.send(Method::GET, path, INVEST, None, &mut browser.clone(), false).await;
		assert!(!answer.headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{path}");
	}
}

async fn user_id(fx: &Surface, browser: &mut Browser) -> uuid::Uuid {
	uuid::Uuid::parse_str(fx.get("/auth/me", browser).await.body["id"].as_str().unwrap()).unwrap()
}

fn sets_the_access_cookie(headers: &axum::http::HeaderMap) -> bool {
	headers.get_all(header::SET_COOKIE).iter().any(|c| c.to_str().unwrap().starts_with("ev_access="))
}

/// Gated as `authz::caller_gate` gates the gRPC surface — and every refusal after the
/// session was read still hands the browser its rotated cookie.
#[tokio::test]
async fn a_disabled_account_or_a_revoked_token_is_refused_at_once() {
	let fx = fixture!();
	let mut browser = signed_in(&fx, &address("gate")).await;
	let id = user_id(&fx, &mut browser).await;

	sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
		.bind(id)
		.execute(&fx.pool)
		.await
		.unwrap();
	for path in ["/auth/me", "/auth/notifications/settings"] {
		let refused = fx.get(path, &mut browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })), "{path}");
		assert!(sets_the_access_cookie(&refused.headers), "{path}: the refusal carries the rotated cookie");
	}
	let write = fx
		.post("/auth/notifications/settings/channel", ORIGIN, json!({ "channel": "email", "enabled": false }), &mut browser)
		.await;
	assert_eq!(write.status, StatusCode::UNAUTHORIZED);

	let mut browser = signed_in(&fx, &address("disabled")).await;
	let id = user_id(&fx, &mut browser).await;
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(id).execute(&fx.pool).await.unwrap();
	let refused = fx.get("/auth/me", &mut browser).await;
	assert_eq!((refused.status, refused.body), (StatusCode::FORBIDDEN, json!({ "error": "disabled" })));
	assert!(sets_the_access_cookie(&refused.headers));
}

#[tokio::test]
async fn reading_the_settings_writes_nothing() {
	let fx = fixture!();
	let mut browser = signed_in(&fx, &address("readonly")).await;
	let id = user_id(&fx, &mut browser).await;
	let rows = || async {
		sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notification_subscribers WHERE user_id = $1")
			.bind(id)
			.fetch_one(&fx.pool)
			.await
			.unwrap()
	};
	let read = fx.get("/auth/notifications/settings", &mut browser).await;
	assert_eq!(read.status, StatusCode::OK);
	assert_eq!(
		(read.body["in_app_enabled"].clone(), read.body["email_enabled"].clone()),
		(json!(true), json!(true)),
		"the defaults a first write creates"
	);
	assert_eq!(rows().await, 0, "a read creates no subscriber");

	let written = fx
		.post("/auth/notifications/settings/channel", ORIGIN, json!({ "channel": "email", "enabled": false }), &mut browser)
		.await;
	assert_eq!(rows().await, 1);
	assert_eq!(
		fx.get("/auth/notifications/settings", &mut browser).await.body,
		written.body,
		"the answered snapshot is the stored one"
	);
}
