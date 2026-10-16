//! `/auth/logout/confirm` — the sign-out a scope's host hands the browser to (publicly
//! `evinvest.ltd/api/auth/logout/confirm`), so that "sign out" on invest or sa ends the
//! `evinvest.ltd` session too and not only the scope's own.
//!
//! A page with one button rather than a link that signs out: the page is reachable from
//! any origin by a plain navigation, and a GET that ended the session would let any page
//! sign a visitor out. The button posts a form back here carrying the session's CSRF
//! token, rendered into the page from the server-side session — never taken from the
//! query, which whoever built the link controls. `return_to` is held to the rules of an
//! absolute `returnTo` (a scope origin plus one of that scope's return paths, or a path on
//! this origin) before anything is rendered or redirected to.

use axum::{
	Form,
	extract::{Query, State},
	http::{HeaderValue, StatusCode, header},
	response::{Html, IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::web::{
	WebState,
	oauth::safe_return_to,
	routes::{CsrfOutcome, clear_session, close, csrf_outcome_of, is_web_url, same_origin_path},
};

/// Where the form posts: the public path, through the conductor's `/api/auth/*` rewrite.
const PUBLIC_PATH: &str = "/api/auth/logout/confirm";

#[derive(Deserialize)]
pub struct PageQuery {
	return_to: Option<String>,
}

#[derive(Deserialize)]
pub struct ConfirmForm {
	csrf: String,
	return_to: String,
}

/// `GET /auth/logout/confirm?return_to=` — the button, or straight back when there is no
/// session to end.
pub async fn page(State(st): State<WebState>, jar: CookieJar, Query(q): Query<PageQuery>) -> Response {
	let st = &st.inner;
	let Some(target) = q.return_to.as_deref().and_then(|raw| return_target(st, raw)) else {
		return refused(StatusCode::BAD_REQUEST, "This sign-out link is not valid.");
	};
	let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_owned()) else {
		return see_other(&target);
	};
	let csrf = match st.sessions.csrf(&id).await {
		Ok(Some(csrf)) => csrf,
		// The cookie names a session the locker no longer holds: already signed out.
		Ok(None) => return (clear_session(st, jar), see_other(&target)).into_response(),
		Err(e) => {
			tracing::error!(error = ?e, "sign-out page: session store failed");
			return refused(StatusCode::SERVICE_UNAVAILABLE, "Signing out is not available right now. Please try again.");
		}
	};
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign out</title></head>\
		 <body><main><h1>Sign out of EV Investment</h1><p>You will be signed out on every EV Investment site in this browser.</p>\
		 <form method=\"post\" action=\"{PUBLIC_PATH}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\">\
		 <button type=\"submit\">Sign out</button></form></main></body></html>",
		escape(&csrf),
		escape(&target),
	);
	(StatusCode::OK, guarded(&target), Html(body)).into_response()
}

/// `POST /auth/logout/confirm` — end the session as `/auth/logout` does, then 303 to the
/// re-checked `return_to`.
pub async fn confirm(State(st): State<WebState>, jar: CookieJar, Form(form): Form<ConfirmForm>) -> Response {
	let st = &st.inner;
	let Some(target) = return_target(st, &form.return_to) else {
		return refused(StatusCode::BAD_REQUEST, "This sign-out link is not valid.");
	};
	match csrf_outcome_of(st, &jar, Some(&form.csrf)).await {
		Ok(CsrfOutcome::Ok) => {}
		Ok(CsrfOutcome::NoSession) => return (clear_session(st, jar), see_other(&target)).into_response(),
		Ok(CsrfOutcome::Mismatch) =>
			return refused(
				StatusCode::FORBIDDEN,
				"This sign-out request could not be verified. Please try again from the site you came from.",
			),
		Err(_) => return refused(StatusCode::SERVICE_UNAVAILABLE, "Signing out is not available right now. Please try again."),
	}
	if let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_owned())
		&& let Err(e) = close(st, &id).await
	{
		// Unlike a gate that found the session over, the person asked to sign out and
		// would be told they had while the session lived on: say it did not happen.
		tracing::error!(error = ?e, "sign-out page: session not closed");
		return refused(StatusCode::SERVICE_UNAVAILABLE, "Signing out is not available right now. Please try again.");
	}
	(clear_session(st, jar), see_other(&target)).into_response()
}

/// `raw` as an absolute landing: a scope origin followed by one of that scope's return
/// paths, byte for byte, or this origin followed by a path `safe_return_to` keeps.
fn return_target(st: &super::Inner, raw: &str) -> Option<String> {
	if !is_web_url(raw) {
		return None;
	}
	if let Some(path) = same_origin_path(raw, &st.public_origin) {
		return Some(format!("{}{}", st.public_origin, safe_return_to(Some(path))));
	}
	st.allowlist.current().origins.is_return_target(raw).then(|| raw.to_owned())
}

/// The origin of a target [`return_target`] produced.
fn origin_of(target: &str) -> &str {
	let after_scheme = target.find("://").map_or(0, |i| i + 3);
	target[after_scheme..].find('/').map_or(target, |i| &target[..after_scheme + i])
}

/// The headers of a page on this origin that must never be framed, cached or load
/// anything. `form-action` names the target's origin beside `'self'` because browsers
/// enforce it on the redirect that answers the form, not only on the form's own action.
fn guarded(target: &str) -> [(header::HeaderName, HeaderValue); 4] {
	let csp = format!("default-src 'none'; form-action 'self' {}; frame-ancestors 'none'", origin_of(target));
	[
		(
			header::CONTENT_SECURITY_POLICY,
			HeaderValue::from_str(&csp).unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'; form-action 'self'; frame-ancestors 'none'")),
		),
		(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
		(header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
		(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
	]
}

fn see_other(target: &str) -> Response {
	match HeaderValue::from_str(target) {
		Ok(location) => (
			StatusCode::SEE_OTHER,
			[(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
		)
			.into_response(),
		Err(_) => refused(StatusCode::BAD_REQUEST, "This sign-out link is not valid."),
	}
}

/// A refusal page. The text is fixed: nothing from the request is echoed.
fn refused(status: StatusCode, message: &'static str) -> Response {
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign out</title></head>\
		 <body><main><h1>Sign-out could not continue</h1><p>{message}</p><p><a href=\"/\">Go to evinvest.ltd</a></p></main></body></html>"
	);
	(
		status,
		[
			(
				header::CONTENT_SECURITY_POLICY,
				HeaderValue::from_static("default-src 'none'; form-action 'none'; frame-ancestors 'none'"),
			),
			(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
			(header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
			(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
		],
		Html(body),
	)
		.into_response()
}

/// Text for a double-quoted HTML attribute.
pub(super) fn escape(raw: &str) -> String {
	let mut out = String::with_capacity(raw.len());
	for c in raw.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			c => out.push(c),
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_origin_of_a_landing_is_its_scheme_and_authority() {
		assert_eq!(origin_of("https://invest.evinvest.ltd/cabinet"), "https://invest.evinvest.ltd");
		assert_eq!(origin_of("http://localhost:58843/"), "http://localhost:58843");
		assert_eq!(origin_of("https://evinvest.ltd"), "https://evinvest.ltd");
	}

	#[test]
	fn an_attribute_value_cannot_close_its_quotes() {
		assert_eq!(escape(r#"/a"><script>&'"#), "/a&quot;&gt;&lt;script&gt;&amp;&#39;");
	}
}
