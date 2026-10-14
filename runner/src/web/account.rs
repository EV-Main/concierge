//! The account MFE's routes: who the signed-in account is, and its notification settings.
//!
//! `PUBLIC_ORIGIN` only — none of them is on a scope host's CORS list, and every mutation
//! carries the CSRF double-submit. The reads take none (a double-submit check on a GET can
//! only ever be wrong) but rotate the session as `/auth/session` does, so they answer with
//! the refreshed access cookie under `Cache-Control: no-store` and `Vary: Cookie`.
//!
//! Every answer is JSON, the refusals `{"error":"<code>"}` as on the sign-in routes.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, HeaderName, StatusCode, header},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::{User, Username};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	notification::{settings_of, topic},
	web::{
		WebState,
		routes::{Caller, session_user},
		sign_in::{Refusal, internal, signed_in},
	},
};

const NO_STORE: [(HeaderName, &str); 2] = [(header::CACHE_CONTROL, "no-store"), (header::VARY, "Cookie")];

type Read = Result<(CookieJar, [(HeaderName, &'static str); 2], Json<Value>), Refusal>;
/// A refusal after the session was read still owes the browser its refreshed cookie.
type Write = Result<(CookieJar, Result<Json<Value>, Refusal>), Refusal>;

fn unauthenticated() -> Refusal {
	Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated")
}

async fn reader(st: &super::Inner, jar: &CookieJar) -> Result<Caller, Refusal> {
	session_user(st, jar)
		.await
		.map_err(|_| internal("account: session store failed", "unavailable"))?
		.ok_or_else(unauthenticated)
}

async fn account(st: &super::Inner, caller: &Caller) -> Result<User, Refusal> {
	st.users.find_by_id(caller.id).await.map_err(|e| internal("account: not read", e))?.ok_or_else(unauthenticated)
}

/// `GET /auth/me` — the first-party `GetMe` minus everything an identity document holds:
/// no legal name, phone, birth date, nationality, tax residence or address. The level is
/// here; the evidence behind it is not.
pub async fn me(State(st): State<WebState>, jar: CookieJar) -> Read {
	let st = &st.inner;
	let caller = reader(st, &jar).await?;
	let user = account(st, &caller).await?;
	let body = json!({
		"id": user.id().to_string(),
		"email": user.email().as_str(),
		"email_verified": user.email_verified(),
		"username": user.username().map(Username::as_str),
		"preferred_name": user.preferred_name(),
		"role": caller.role.clone(),
		"role_is_break_glass": caller.role_is_break_glass,
		"kyc_level": user.kyc_level(),
	});
	Ok((caller.refreshed(st, jar), NO_STORE, Json(body)))
}

/// The settings snapshot, the subscriber row created on first touch so a user never has
/// to switch notifications ON before they may switch them off.
async fn settings(st: &super::Inner, user: &User) -> Result<Json<Value>, Refusal> {
	let sub = st
		.notifications
		.subscriber_for_user(user.id().raw(), user.email().as_str(), user.email_verified())
		.await
		.map_err(|e| internal("notification settings: subscriber not read", e))?;
	let settings = settings_of(st.notifications.as_ref(), &sub).await.map_err(|e| internal("notification settings: not read", e))?;
	Ok(Json(json!({
		"in_app_enabled": settings.in_app_enabled,
		"email_enabled": settings.email_enabled,
		"email": settings.email,
		"email_verified": settings.email_verified,
		"topics": settings.topics.iter().map(|t| json!({
			"topic": t.topic,
			"label": t.label,
			"description": t.description,
			"subscribed": t.subscribed,
			"email_enabled": t.email_enabled,
		})).collect::<Vec<_>>(),
	})))
}

/// `GET /auth/notifications/settings`.
pub async fn notification_settings(State(st): State<WebState>, jar: CookieJar) -> Read {
	let st = &st.inner;
	let caller = reader(st, &jar).await?;
	let user = account(st, &caller).await?;
	let body = settings(st, &user).await?;
	Ok((caller.refreshed(st, jar), NO_STORE, body))
}

#[derive(Deserialize)]
pub struct ChannelChange {
	channel: String,
	enabled: bool,
}

/// `POST /auth/notifications/settings/channel` — answers the whole snapshot, re-read, so
/// the screen renders what the database holds. Both channels off is allowed: "stop
/// contacting me" is a supported state.
pub async fn set_channel(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<ChannelChange>) -> Write {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let answer = async {
		let (in_app, email) = match body.channel.as_str() {
			"in_app" => (Some(body.enabled), None),
			"email" => (None, Some(body.enabled)),
			_ => return Err(Refusal::new(StatusCode::BAD_REQUEST, "invalid_channel")),
		};
		let user = account(st, &caller).await?;
		let sub = st
			.notifications
			.subscriber_for_user(user.id().raw(), user.email().as_str(), user.email_verified())
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		st.notifications
			.set_channel_enabled(sub.id, in_app, email)
			.await
			.map_err(|e| internal("notification settings: channel not set", e))?;
		settings(st, &user).await
	}
	.await;
	Ok((caller.refreshed(st, jar), answer))
}

#[derive(Deserialize)]
pub struct TopicChange {
	topic: String,
	subscribed: bool,
	email_enabled: bool,
}

/// `POST /auth/notifications/settings/topic` — a catalogue topic only; answers the whole
/// snapshot.
pub async fn set_topic(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<TopicChange>) -> Write {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let answer = async {
		if topic(&body.topic).is_none() {
			return Err(Refusal::new(StatusCode::BAD_REQUEST, "unknown_topic"));
		}
		let user = account(st, &caller).await?;
		let sub = st
			.notifications
			.subscriber_for_user(user.id().raw(), user.email().as_str(), user.email_verified())
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		st.notifications
			.set_topic_subscription(sub.id, &body.topic, body.subscribed, body.email_enabled)
			.await
			.map_err(|e| internal("notification settings: topic not set", e))?;
		settings(st, &user).await
	}
	.await;
	Ok((caller.refreshed(st, jar), answer))
}
