//! The account-less notification edge: the subscribe form a scope's page posts to and the
//! two links every topic mail carries (publicly `evinvest.ltd/api/auth/notifications/*`).
//!
//! Served here, in process, rather than through `NotificationService`'s account-less RPCs:
//! those want a `typ=service` token this plane does not mint yet. The logic is the same
//! functions either way (`notification::subscribe_accountless`, `unsubscribe_by_token`).
//!
//! The links open a page with one button, and only its POST changes anything: mail
//! scanners fetch every link in a message, and a GET that confirmed would verify an
//! address its owner never saw, one that unsubscribed would silence it. The one exception
//! is RFC 8058's one-click unsubscribe, which is itself a POST — the mail client sends
//! `List-Unsubscribe=One-Click` to the URL in the header, the token in its query — and
//! wants a 200, not a redirect. No `Origin` check on the two POSTs: the mail client sends
//! none, and the token, a secret only the mailbox holds, is the whole authority.
//!
//! Tokens never reach a log line and are rendered only through [`escape`].

use axum::{
	Form, Json,
	body::Bytes,
	extract::{Query, State},
	http::{HeaderMap, HeaderValue, StatusCode, header},
	response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	notification::{SubscribeRefusal, UnsubscribeRefusal, subscribe_accountless, unsubscribe_by_token},
	web::{
		WebState,
		logout::escape,
		routes::ClientIp,
		sign_in::{Refusal, guard, internal},
	},
};

/// Where the pages' forms post: the public paths, through the conductor's `/api/auth/*`
/// rewrite.
const CONFIRM_PATH: &str = "/api/auth/notifications/confirm";
const UNSUBSCRIBE_PATH: &str = "/api/auth/notifications/unsubscribe";

#[derive(Deserialize)]
pub struct TokenQuery {
	#[serde(default)]
	token: String,
	#[serde(default)]
	topic: String,
}

#[derive(Deserialize)]
pub struct ConfirmForm {
	#[serde(default)]
	token: String,
}

/// `GET /auth/notifications/confirm?token=` — the button; confirms nothing by itself.
pub async fn confirm_page(Query(q): Query<TokenQuery>) -> Response {
	if q.token.is_empty() {
		return answer(StatusCode::BAD_REQUEST, "Confirm subscription", "This confirmation link is not valid.");
	}
	page(
		"Confirm subscription",
		"Press the button to start receiving these emails from EV Investment.",
		CONFIRM_PATH,
		&[("token", &q.token)],
		"Confirm subscription",
	)
}

/// `POST /auth/notifications/confirm` (form `token`). A token nobody holds and one already
/// spent read alike: the table cannot tell them apart either.
pub async fn confirm(State(st): State<WebState>, Form(form): Form<ConfirmForm>) -> Response {
	if form.token.is_empty() {
		return answer(StatusCode::BAD_REQUEST, "Confirm subscription", "This confirmation link is not valid.");
	}
	match st.inner.notifications.confirm(&form.token).await {
		Ok(true) => answer(StatusCode::OK, "Subscription confirmed", "You will receive these emails from EV Investment."),
		Ok(false) => answer(
			StatusCode::OK,
			"Confirm subscription",
			"This link has already been used or is no longer valid. If you confirmed before, you are subscribed.",
		),
		Err(e) => {
			tracing::error!(error = %e, "account-less confirm failed");
			unavailable("Confirm subscription")
		}
	}
}

/// `GET /auth/notifications/unsubscribe?token=[&topic=]` — the button; unsubscribes nothing
/// by itself.
pub async fn unsubscribe_page(Query(q): Query<TokenQuery>) -> Response {
	if q.token.is_empty() {
		return answer(StatusCode::BAD_REQUEST, "Unsubscribe", "This unsubscribe link is not valid.");
	}
	page(
		"Unsubscribe",
		"Press the button to stop receiving these emails from EV Investment. Your notifications in the cabinet are not affected.",
		UNSUBSCRIBE_PATH,
		&[("token", &q.token), ("topic", &q.topic)],
		"Unsubscribe",
	)
}

/// `POST /auth/notifications/unsubscribe` — the page's button (form `token`, `topic`) or a
/// mail client's one-click (`List-Unsubscribe=One-Click`, token and topic in the query).
/// A form field wins over the query's. A token nobody holds gets the same 200 as one that
/// unsubscribed: whether an address is on the list is not the caller's to learn.
pub async fn unsubscribe(State(st): State<WebState>, Query(q): Query<TokenQuery>, headers: HeaderMap, body: Bytes) -> Response {
	let (mut token, mut topic) = (q.token, q.topic);
	// RFC 8058 allows `multipart/form-data` too; such a body carries only the one-click
	// marker, and the token is in the query either way, so it is not read.
	let urlencoded = headers
		.get(header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
	if urlencoded {
		for (key, value) in form_urlencoded::parse(&body) {
			match key.as_ref() {
				"token" if !value.is_empty() => token = value.into_owned(),
				"topic" if !value.is_empty() => topic = value.into_owned(),
				_ => {}
			}
		}
	}
	match unsubscribe_by_token(st.inner.notifications.as_ref(), &token, &topic).await {
		Ok(Ok(_)) => answer(
			StatusCode::OK,
			"Unsubscribed",
			"You will not receive these emails any more. Your notifications in the cabinet are not affected.",
		),
		Ok(Err(UnsubscribeRefusal::MissingToken)) => answer(StatusCode::BAD_REQUEST, "Unsubscribe", "This unsubscribe link is not valid."),
		Ok(Err(UnsubscribeRefusal::UnknownTopic)) => answer(StatusCode::BAD_REQUEST, "Unsubscribe", "This unsubscribe link names a topic that does not exist."),
		Err(e) => {
			tracing::error!(error = %e, "account-less unsubscribe failed");
			unavailable("Unsubscribe")
		}
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeRequest {
	email: String,
	topic: String,
	turnstile_token: String,
}

/// `POST /auth/notifications/subscribe` — "email me about this" without an account, from
/// this origin or a scope's host. Double opt-in: the address gets one throttled
/// confirmation mail and nothing else until its link is pressed. Answers `{accepted: true}`
/// for a new address, a confirmed one and a throttled one alike.
pub async fn subscribe(State(st): State<WebState>, headers: HeaderMap, ip: ClientIp, Json(body): Json<SubscribeRequest>) -> Result<Json<Value>, Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, Some(&body.turnstile_token)).await?;
	let accepted = subscribe_accountless(st.notifications.as_ref(), &st.subscribe_limiter, &body.email, &body.topic, &ip.0)
		.await
		.map_err(|e| internal("account-less subscribe failed", e))?
		.map_err(|refusal| match refusal {
			SubscribeRefusal::UnknownTopic => Refusal::new(StatusCode::BAD_REQUEST, "unknown_topic"),
			SubscribeRefusal::InvalidEmail => Refusal::new(StatusCode::BAD_REQUEST, "invalid_email"),
			SubscribeRefusal::TooMany => Refusal::new(StatusCode::TOO_MANY_REQUESTS, "throttled"),
		})?;
	if accepted.queued() {
		st.mail_wake.notify_one();
	}
	Ok(Json(json!({ "accepted": true })))
}

/// A page with one button posting `fields` to `action`.
fn page(title: &str, text: &str, action: &str, fields: &[(&str, &str)], button: &str) -> Response {
	let hidden: String = fields
		.iter()
		.filter(|(_, value)| !value.is_empty())
		.map(|(name, value)| format!("<input type=\"hidden\" name=\"{name}\" value=\"{}\">", escape(value)))
		.collect();
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head>\
		 <body><main><h1>{title}</h1><p>{text}</p><form method=\"post\" action=\"{action}\">{hidden}<button type=\"submit\">{button}</button></form></main></body></html>"
	);
	(StatusCode::OK, guarded(), Html(body)).into_response()
}

/// An outcome page. The text is fixed: nothing from the request is echoed.
fn answer(status: StatusCode, title: &'static str, message: &'static str) -> Response {
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head>\
		 <body><main><h1>{title}</h1><p>{message}</p><p><a href=\"/\">Go to evinvest.ltd</a></p></main></body></html>"
	);
	(status, guarded(), Html(body)).into_response()
}

fn unavailable(title: &'static str) -> Response {
	answer(StatusCode::SERVICE_UNAVAILABLE, title, "This is not available right now. Please try the link again later.")
}

/// Never framed, cached or loading anything, and no `Referer` carrying the token in the
/// page's URL to wherever the "Go to" link leads.
fn guarded() -> [(header::HeaderName, HeaderValue); 4] {
	[
		(
			header::CONTENT_SECURITY_POLICY,
			HeaderValue::from_static("default-src 'none'; form-action 'self'; frame-ancestors 'none'"),
		),
		(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
		(header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
		(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
	]
}
