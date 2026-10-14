//! The account MFE's routes: who the signed-in account is, and its notification settings.
//!
//! `PUBLIC_ORIGIN` only — none of them is on a scope host's CORS list, and every mutation
//! carries the CSRF double-submit. The reads take none (a double-submit check on a GET can
//! only ever be wrong) but rotate the session as `/auth/session` does, so every answer
//! after the session was read — a refusal included — carries the refreshed access cookie;
//! the reads also go out under `Cache-Control: no-store` and `Vary: Cookie`.
//!
//! The caller is gated as `authz::caller_gate` gates the gRPC surface: a disabled account,
//! or a session whose token predates the account's `token_version`, is refused at once,
//! not when its access token next expires. On a read that refusal also ends the session
//! and clears its cookies, as a sign-out does: the session has nothing left to answer.
//!
//! Every answer is JSON, the refusals `{"error":"<code>"}` as on the sign-in routes.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, HeaderName, StatusCode, header},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::{User, UserStatus, Username};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	notification::{settings_json, settings_of, subscriber_of, topic},
	web::{
		WebState,
		routes::{Caller, clear_session, close, session_user},
		sign_in::{Answered, Refusal, internal, signed_in},
	},
};

const NO_STORE: [(HeaderName, &str); 2] = [(header::CACHE_CONTROL, "no-store"), (header::VARY, "Cookie")];

/// The outer refusal is for a request that never reached a session; the inner one comes
/// after it, beside the cookies the read rotated or cleared.
type Read = Result<(CookieJar, [(HeaderName, &'static str); 2], Result<Json<Value>, Refusal>), Refusal>;

/// Why the gate refused: the session is over, or something else went wrong.
enum Denied {
	SessionOver(Refusal),
	Other(Refusal),
}

impl From<Refusal> for Denied {
	fn from(refusal: Refusal) -> Self {
		Self::Other(refusal)
	}
}

impl From<Denied> for Refusal {
	fn from(denied: Denied) -> Self {
		match denied {
			Denied::SessionOver(refusal) | Denied::Other(refusal) => refusal,
		}
	}
}

fn unauthenticated() -> Refusal {
	Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated")
}

/// The caller's account, gated: `caller_gate`'s two refusals, in its order.
async fn account(st: &super::Inner, caller: &Caller) -> Result<User, Denied> {
	let user = st.users.find_by_id(caller.id).await.map_err(|e| internal("account: not read", e))?.ok_or_else(unauthenticated)?;
	if user.status() == UserStatus::Disabled {
		return Err(Denied::SessionOver(Refusal::new(StatusCode::FORBIDDEN, "disabled")));
	}
	if caller.minted_token_version.is_none_or(|minted| minted < user.token_version()) {
		return Err(Denied::SessionOver(unauthenticated()));
	}
	Ok(user)
}

/// A read's answer and the cookies that go with it: rotated, or — when the gate found the
/// session over — the session closed and its cookies cleared.
async fn read_answer(st: &super::Inner, jar: CookieJar, caller: Caller, answer: Result<Json<Value>, Denied>) -> Read {
	match answer {
		Ok(body) => Ok((caller.refreshed(st, jar), NO_STORE, Ok(body))),
		Err(Denied::Other(refusal)) => Ok((caller.refreshed(st, jar), NO_STORE, Err(refusal))),
		Err(Denied::SessionOver(refusal)) => {
			if let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_owned())
				&& let Err(e) = close(st, &id).await
			{
				// The cookies are cleared regardless; a session the store still holds dies
				// at its next refresh, which re-reads the same account.
				tracing::error!(error = ?e, "account: session over but not closed");
			}
			Ok((clear_session(st, jar), NO_STORE, Err(refusal)))
		}
	}
}

async fn reader(st: &super::Inner, jar: &CookieJar) -> Result<Caller, Refusal> {
	session_user(st, jar)
		.await
		.map_err(|_| internal("account: session store failed", "unavailable"))?
		.ok_or_else(unauthenticated)
}

/// `GET /auth/me` — the first-party `GetMe` minus everything an identity document holds:
/// no legal name, phone, birth date, nationality, tax residence or address. The level is
/// here; the evidence behind it is not.
pub async fn me(State(st): State<WebState>, jar: CookieJar) -> Read {
	let st = &st.inner;
	let caller = reader(st, &jar).await?;
	let answer = account(st, &caller).await.map(|user| {
		Json(json!({
			"id": user.id().to_string(),
			"email": user.email().as_str(),
			"email_verified": user.email_verified(),
			"username": user.username().map(Username::as_str),
			"preferred_name": user.preferred_name(),
			"role": caller.role,
			"role_is_break_glass": caller.role_is_break_glass,
			"kyc_level": user.kyc_level(),
		}))
	});
	read_answer(st, jar, caller, answer).await
}

/// `GET /auth/notifications/settings` — written nowhere: an account that never touched
/// its settings reads the defaults its first change would create.
pub async fn notification_settings(State(st): State<WebState>, jar: CookieJar) -> Read {
	let st = &st.inner;
	let caller = reader(st, &jar).await?;
	let answer = async {
		let user = account(st, &caller).await?;
		let sub = st
			.notifications
			.subscriber_of_user(user.id().raw())
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		let settings = settings_of(st.notifications.as_ref(), user.email().as_str(), user.email_verified(), sub.as_ref())
			.await
			.map_err(|e| internal("notification settings: not read", e))?;
		Ok::<_, Denied>(Json(settings_json(&settings)))
	}
	.await;
	read_answer(st, jar, caller, answer).await
}

#[derive(Deserialize)]
pub struct ChannelChange {
	channel: String,
	enabled: bool,
}

/// `POST /auth/notifications/settings/channel` — answers the whole snapshot. Both channels
/// off is allowed: "stop contacting me" is a supported state.
pub async fn set_channel(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<ChannelChange>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let answer = async {
		let (in_app, email) = match body.channel.as_str() {
			"in_app" => (Some(body.enabled), None),
			"email" => (None, Some(body.enabled)),
			_ => return Err(Refusal::new(StatusCode::BAD_REQUEST, "invalid_channel")),
		};
		let user = account(st, &caller).await.map_err(Refusal::from)?;
		let mut sub = subscriber_of(st.notifications.as_ref(), &user)
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		st.notifications
			.set_channel_enabled(sub.id, in_app, email)
			.await
			.map_err(|e| internal("notification settings: channel not set", e))?;
		// The one column this request wrote, set on the row in hand rather than re-read.
		sub.in_app_enabled = in_app.unwrap_or(sub.in_app_enabled);
		sub.email_enabled = email.unwrap_or(sub.email_enabled);
		let settings = settings_of(st.notifications.as_ref(), &sub.email, sub.email_verified, Some(&sub))
			.await
			.map_err(|e| internal("notification settings: not read", e))?;
		Ok(Json(settings_json(&settings)))
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
pub async fn set_topic(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<TopicChange>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let answer = async {
		if topic(&body.topic).is_none() {
			return Err(Refusal::new(StatusCode::BAD_REQUEST, "unknown_topic"));
		}
		let user = account(st, &caller).await.map_err(Refusal::from)?;
		let sub = subscriber_of(st.notifications.as_ref(), &user)
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		st.notifications
			.set_topic_subscription(sub.id, &body.topic, body.subscribed, body.email_enabled)
			.await
			.map_err(|e| internal("notification settings: topic not set", e))?;
		let settings = settings_of(st.notifications.as_ref(), &sub.email, sub.email_verified, Some(&sub))
			.await
			.map_err(|e| internal("notification settings: not read", e))?;
		Ok(Json(settings_json(&settings)))
	}
	.await;
	Ok((caller.refreshed(st, jar), answer))
}
