//! The account MFE's routes: who the signed-in account is, and its notification settings.
//!
//! None of them is on a scope host's CORS list, and every mutation carries the CSRF
//! double-submit. The notification routes still read the `Origin` to decide WHICH inbox
//! they answer for (D21, [`InboxView`]): `PUBLIC_ORIGIN` (or none — a same-origin GET
//! sends none) is the platform's, a scope's host is that scope's, and anything else is
//! refused. The reads take none (a double-submit check on a GET can
//! only ever be wrong) but rotate the session as `/auth/session` does, so every answer
//! after the session was read — a refusal included — carries the refreshed access cookie;
//! the reads also go out under `Cache-Control: no-store` and `Vary: Cookie`.
//!
//! The caller is gated as `authz::caller_gate` gates the gRPC surface: a disabled account,
//! or a session whose token predates the account's `token_version`, is refused at once,
//! not when its access token next expires. That refusal also ends the session and clears
//! its cookies, as a sign-out does, on a read and a mutation alike: the session has
//! nothing left to answer (`sign_in::gate`, shared with every signed-in mutation).
//!
//! Every answer is JSON, the refusals `{"error":"<code>"}` as on the sign-in routes.

use axum::{
	Json,
	extract::{Query, State},
	http::{HeaderMap, HeaderName, StatusCode, header},
};
use axum_extra::extract::cookie::CookieJar;
use domain::{
	authz::Notifications as NotificationPermission,
	users::{User, Username},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	notification::{InboxView, TopicChangeRefusal, check_topic_change, current_key, settings_json, settings_of, subscriber_of},
	web::{
		WebState,
		routes::{Caller, session_user},
		sign_in::{Answered, Denied, Refusal, Signed, end_session, gate, internal, signed_in},
	},
};

const NO_STORE: [(HeaderName, &str); 2] = [(header::CACHE_CONTROL, "no-store"), (header::VARY, "Cookie")];

/// The outer refusal is for a request that never reached a session; the inner one comes
/// after it, beside the cookies the read rotated or cleared.
type Read = Result<(CookieJar, [(HeaderName, &'static str); 2], Result<Json<Value>, Refusal>), Refusal>;

/// A read's answer and the cookies that go with it: rotated, or — when the gate found the
/// session over — the session closed and its cookies cleared.
async fn read_answer(st: &super::Inner, jar: CookieJar, caller: Caller, answer: Result<Json<Value>, Denied>) -> Read {
	match answer {
		Ok(body) => Ok((caller.refreshed(st, jar), NO_STORE, Ok(body))),
		Err(Denied::Other(refusal)) => Ok((caller.refreshed(st, jar), NO_STORE, Err(refusal))),
		Err(Denied::SessionOver(refusal)) => Ok((end_session(st, jar).await, NO_STORE, Err(refusal))),
	}
}

fn unauthenticated() -> Refusal {
	Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated")
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
	let answer = gate(st, &caller).await.map(|user| {
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

/// `?all=1` asks for the summary inbox. Taken as raw pairs rather than a struct so a
/// repeated `all` is this route's JSON refusal, not the extractor's plain-text 400.
type ViewQuery = Vec<(String, String)>;

/// The inbox a request on the notification routes is answered from. The summary is served
/// on `PUBLIC_ORIGIN` only, to a PERSISTED seat holding the permission: break-glass
/// elevation opens the console, not everyone's notifications.
async fn inbox_view(st: &super::Inner, headers: &HeaderMap, query: &ViewQuery, user: &User) -> Result<InboxView, Refusal> {
	let forbidden = || Refusal::new(StatusCode::FORBIDDEN, "forbidden");
	let mut all = query.iter().filter(|(key, _)| key == "all").map(|(_, value)| value.as_str());
	let summary = match (all.next(), all.next()) {
		(None | Some("0" | "false"), None) => false,
		(Some("1" | "true"), None) => true,
		_ => return Err(Refusal::new(StatusCode::BAD_REQUEST, "invalid_view")),
	};
	let not_allowed = || Refusal::new(StatusCode::FORBIDDEN, "origin_not_allowed");
	let origin = headers.get(header::ORIGIN).map(|v| v.to_str().map_err(|_| not_allowed())).transpose()?;
	let scope = match origin {
		None => None,
		Some(origin) if origin == st.public_origin => None,
		Some(origin) => {
			let allowlist = st.allowlist.current();
			let (id, namespace) = allowlist.origins.scope_of(origin).ok_or_else(not_allowed)?;
			Some((id.to_owned(), namespace.to_owned()))
		}
	};
	match (scope, summary) {
		(Some(_), true) => Err(forbidden()),
		(Some((id, namespace)), false) => InboxView::of_scope(st.notifications.as_ref(), &id, &namespace, user.id().raw())
			.await
			.map_err(|e| internal("notification settings: scope membership not read", e)),
		(None, true) if user.role().may(NotificationPermission::ReadAll) => Ok(InboxView::All),
		(None, true) => Err(forbidden()),
		(None, false) => Ok(InboxView::Platform),
	}
}

/// `GET /auth/notifications/settings` — written nowhere: an account that never touched
/// its settings reads the defaults its first change would create.
pub async fn notification_settings(State(st): State<WebState>, Query(query): Query<ViewQuery>, jar: CookieJar, headers: HeaderMap) -> Read {
	let st = &st.inner;
	let caller = reader(st, &jar).await?;
	let answer = async {
		let user = gate(st, &caller).await?;
		let view = inbox_view(st, &headers, &query, &user).await?;
		let sub = st
			.notifications
			.subscriber_of_user(user.id().raw())
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		let settings = settings_of(st.notifications.as_ref(), &view, user.email().as_str(), user.email_verified(), sub.as_ref())
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
/// off is allowed: "stop contacting me" is a supported state. Not from a scope's host: a
/// switch there would silence every other inbox too.
pub async fn set_channel(State(st): State<WebState>, Query(query): Query<ViewQuery>, jar: CookieJar, headers: HeaderMap, Json(body): Json<ChannelChange>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in(st, &jar, &headers).await?;
	let answer = async {
		let view = inbox_view(st, &headers, &query, &user).await?;
		if !view.sets_channels() {
			return Err(Refusal::new(StatusCode::FORBIDDEN, "platform_only"));
		}
		let (in_app, email) = match body.channel.as_str() {
			"in_app" => (Some(body.enabled), None),
			"email" => (None, Some(body.enabled)),
			_ => return Err(Refusal::new(StatusCode::BAD_REQUEST, "invalid_channel")),
		};
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
		let settings = settings_of(st.notifications.as_ref(), &view, &sub.email, sub.email_verified, Some(&sub))
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

/// `POST /auth/notifications/settings/topic` — a topic the request's inbox offers; answers
/// that inbox's whole snapshot. A topic of another inbox is as unknown as a made-up one;
/// switching a required topic (or its mail copy) off is `409 required_topic`.
pub async fn set_topic(State(st): State<WebState>, Query(query): Query<ViewQuery>, jar: CookieJar, headers: HeaderMap, Json(body): Json<TopicChange>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in(st, &jar, &headers).await?;
	let answer = async {
		let view = inbox_view(st, &headers, &query, &user).await?;
		let key = current_key(&body.topic);
		match check_topic_change(st.notifications.as_ref(), &view, key, body.subscribed, body.email_enabled)
			.await
			.map_err(|e| internal("notification settings: topics not read", e))?
		{
			Ok(()) => {}
			Err(TopicChangeRefusal::Unknown) => return Err(Refusal::new(StatusCode::BAD_REQUEST, "unknown_topic")),
			// 409: the request is well formed and the caller may make it; the topic's state
			// is what refuses it.
			Err(TopicChangeRefusal::Required) => return Err(Refusal::new(StatusCode::CONFLICT, "required_topic")),
		}
		let sub = subscriber_of(st.notifications.as_ref(), &user)
			.await
			.map_err(|e| internal("notification settings: subscriber not read", e))?;
		st.notifications
			.set_topic_subscription(sub.id, key, body.subscribed, body.email_enabled)
			.await
			.map_err(|e| internal("notification settings: topic not set", e))?;
		let settings = settings_of(st.notifications.as_ref(), &view, &sub.email, sub.email_verified, Some(&sub))
			.await
			.map_err(|e| internal("notification settings: not read", e))?;
		Ok(Json(settings_json(&settings)))
	}
	.await;
	Ok((caller.refreshed(st, jar), answer))
}
