//! `GET /auth/authorize` — the browser-facing half of the relying-party code flow
//! (publicly `evinvest.ltd/api/auth/authorize`, through the conductor's existing
//! `/api/auth/*` rewrite).
//!
//! The ONE property this route exists to keep: it never sends a browser to an address
//! that is not registered, byte for byte, for the client named. So the client and the
//! redirect_uri are settled FIRST, and anything wrong with either is answered with a page
//! on this origin, never a redirect. Only once the redirect_uri is known to be the
//! client's own does an error travel back to it (`error=…&state=…`), the way OAuth
//! clients expect to receive one.
//!
//! Signing in is not re-implemented: a browser with no session is sent to the ordinary
//! `/api/auth/login` with `returnTo` pointing back here, which `safe_return_to` already
//! admits (a same-origin path). The Google client never learns a relying party exists.
//! `prompt=select_account` sends a signed-in browser the same way, to switch accounts.
//!
//! `max_age=N` (OIDC) asks for a session whose `auth_time` is at most N seconds old;
//! `max_age=0` always asks. An older one is not signed in again — a new sign-in would end
//! the browser's session and every client session with it — but sent to the confirmation
//! page ([`CONFIRM_PATH`]), which runs the ordinary re-authentication (`/auth/reauth/*`,
//! `PUBLIC_ORIGIN` only) and comes back here. This route remembers the trip it started
//! (session, client, PKCE challenge) and takes it back once; only a code issued at the
//! end of a trip whose confirmation moved `auth_time` after it began carries `auth_time`,
//! and with it every access token the client gets for it. That is how a client proves the
//! person confirmed for IT (`approvals`, D24(1)): an `auth_time` this client did not ask
//! for — a sign-in, a re-authentication for banking — never reaches its tokens, so a
//! client cannot spend another's proof or pass an ordinary sign-in off as one.

use axum::{
	Json,
	extract::{Path, Query, State},
	http::{HeaderMap, HeaderValue, StatusCode, header},
	response::{Html, IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
	relying_party::{Admission, Requester, is_s256_challenge},
	web::{
		WebState, now_secs,
		routes::{ClientIp, live_family_of, minted_auth_time, minted_token_version},
		session::Fresh,
		sign_in::end_session,
	},
};

/// The public path of this route — what `returnTo` must name for the login to come back.
const PUBLIC_PATH: &str = "/api/auth/authorize";
/// The public path of the ordinary login.
const LOGIN_PATH: &str = "/api/auth/login";
/// OAuth `state` is the client's opaque value; bounded so it stays a value.
const MAX_STATE_LEN: usize = 512;
/// The page on this origin that asks the signed-in person to confirm it is them
/// (`mfe-concierge-reauth`) and then, confirmed or not, sends the browser to its
/// `return_to` — always a path back to this route, built here.
pub const CONFIRM_PATH: &str = "/api/auth/mfe/reauth.html";
/// How long a confirmation trip may take. A trip not back by then is forgotten, and the
/// browser that comes back later starts a new one.
pub const TRIP_TTL_SECS: u64 = 600;
/// How far ahead of this replica's clock a confirmation may be dated: the replica that
/// moved `auth_time` may run a little ahead of this one.
const CLOCK_SKEW_SECS: i64 = 30;
/// Ten digits is over three hundred years; anything longer is not an age.
const MAX_AGE_DIGITS: usize = 10;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
	client_id: Option<String>,
	redirect_uri: Option<String>,
	response_type: Option<String>,
	state: Option<String>,
	code_challenge: Option<String>,
	code_challenge_method: Option<String>,
	/// OIDC `prompt`: `select_account` alone, for a browser that may already be signed in
	/// as somebody else.
	prompt: Option<String>,
	/// OIDC `max_age`, in seconds. A string, so a malformed one goes back to the client as
	/// `invalid_request` instead of failing the whole request here.
	max_age: Option<String>,
	/// Set by the login callback when the sign-in itself failed or was cancelled.
	auth_error: Option<String>,
}

pub async fn authorize(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ClientIp(ip): ClientIp, Query(q): Query<AuthorizeQuery>) -> Response {
	let st = &st.inner;
	let Some(relying_parties) = st.relying_parties.as_ref() else {
		return page(StatusCode::SERVICE_UNAVAILABLE, "Sign-in for this application is not available right now.");
	};
	let (Some(client_id), Some(redirect_uri)) = (q.client_id.as_deref(), q.redirect_uri.as_deref()) else {
		return page(StatusCode::BAD_REQUEST, "This sign-in link is incomplete.");
	};
	let client = match relying_parties.resolve(client_id, redirect_uri).await {
		Ok(Some(client)) => client,
		Ok(None) => {
			// Debug, not Display: the caller's own string, and it may carry newlines.
			tracing::warn!(client_id = ?client_id.chars().take(32).collect::<String>(), "relying party: authorize refused an unregistered client or redirect_uri");
			return page(StatusCode::BAD_REQUEST, "This sign-in link is not valid.");
		}
		Err(err) => {
			tracing::error!(%err, "relying party: registry unreadable at authorize");
			return page(StatusCode::SERVICE_UNAVAILABLE, "Sign-in for this application is not available right now.");
		}
	};

	// The redirect_uri is the client's own from here on. `state` is REQUIRED: it is the
	// client's only defence against a code injected into its callback, and a client that
	// forgot it is better told so now than left open.
	let state = q.state.as_deref().filter(|s| !s.is_empty() && s.len() <= MAX_STATE_LEN);
	let back = Back { redirect_uri, state };
	if state.is_none() {
		return back.error("invalid_request");
	}
	match q.response_type.as_deref() {
		Some("code") => {}
		None => return back.error("invalid_request"),
		Some(_) => return back.error("unsupported_response_type"),
	}
	let Some(code_challenge) = q.code_challenge.as_deref().filter(|c| is_s256_challenge(c)) else {
		return back.error("invalid_request");
	};
	if q.code_challenge_method.as_deref() != Some("S256") {
		return back.error("invalid_request");
	}
	let max_age = match q.max_age.as_deref().map(parse_max_age) {
		None => None,
		Some(Some(max_age)) => Some(max_age),
		Some(None) => return back.error("invalid_request"),
	};
	let asked = Asked {
		client_id,
		redirect_uri,
		state,
		code_challenge,
		max_age,
	};
	// The chooser leads to a new sign-in, which can complete without the person doing
	// anything (a provider's remembered account), so it never stands in for a confirmation.
	if q.prompt.is_some() && max_age.is_some() {
		return back.error("invalid_request");
	}
	match q.prompt.as_deref() {
		None => {}
		// Google's chooser is on every login; the way back drops `prompt`, so it authorizes.
		Some("select_account") => return redirect(&asked.login_url()),
		Some(_) => return back.error("invalid_request"),
	}

	let session_id = jar.get(&st.cookies.session).map(|c| c.value().to_string());
	let live = match session_id.as_deref() {
		Some(id) => match live_session(st, id).await {
			Ok(live) => live.map(|(fresh, family)| (id, fresh, family)),
			Err(err) => {
				tracing::error!(error = ?err, "relying party: session unreadable at authorize");
				return back.error("temporarily_unavailable");
			}
		},
		None => None,
	};
	let Some((session_id, fresh, upstream_family)) = live else {
		// Coming back from a sign-in that failed or was cancelled: send the refusal to the
		// client rather than start the login again, which would loop.
		if q.auth_error.is_some() {
			return back.error("access_denied");
		}
		return redirect(&asked.login_url());
	};
	let minted = minted_token_version(&fresh.access_token);
	let auth_time = minted_auth_time(&fresh.access_token);
	// The session view may have rotated the access token; the browser gets the new one
	// exactly as `/auth/session` hands it out, whatever this route answers.
	let refreshed = jar.clone().add(st.cookies.server_cookie(st.cookies.access.clone(), fresh.access_token, fresh.remaining_secs));

	let Ok(user) = Uuid::parse_str(&fresh.user.user_id).map(UserId::from_raw) else {
		return (refreshed, back.error("access_denied")).into_response();
	};
	let token_version = match relying_parties.admit(user).await {
		// A takeover or a revoke-all bumps `token_version` but leaves the family in place
		// until its next refresh, so the family check above still passes for as long as
		// the cached access token lives. Refused as `sign_in::gate` refuses it: the
		// session is over, and a code minted at the CURRENT version would hand the old
		// session's holder (a squatter) the account it lost.
		Ok(Admission::Admitted { token_version }) if minted.is_none_or(|minted| minted < token_version) => {
			tracing::info!(client_id = %client.client_id, user_id = %user, "relying party: authorize refused a session minted before the account's token_version");
			let cleared = end_session(st, jar).await;
			return (cleared, page(StatusCode::UNAUTHORIZED, "Your session has ended. Sign in again.")).into_response();
		}
		Ok(Admission::Admitted { token_version }) => token_version,
		Ok(Admission::Denied) => {
			tracing::info!(client_id = %client.client_id, user_id = %user, "relying party: authorize denied, the account is not active");
			return (refreshed, back.error("access_denied")).into_response();
		}
		Err(err) => {
			tracing::error!(%err, "relying party: account unreadable at authorize");
			return (refreshed, back.error("temporarily_unavailable")).into_response();
		}
	};
	let mut confirmed = None;
	if let Some(max_age) = max_age {
		let trip = trip_key(session_id, client_id, code_challenge);
		let started = match st.sessions.take_trip(&trip).await {
			Ok(started) => started,
			Err(err) => {
				tracing::error!(error = ?err, "relying party: confirmation trip unreadable at authorize");
				return (refreshed, back.error("temporarily_unavailable")).into_response();
			}
		};
		let now = now_secs();
		match decide(max_age, auth_time, started, now) {
			Decision::Code => {}
			Decision::Confirmed(at) => confirmed = Some(at),
			Decision::Confirm => {
				if let Err(err) = st.sessions.start_trip(&trip, now, TRIP_TTL_SECS).await {
					tracing::error!(error = ?err, "relying party: confirmation trip not stored at authorize");
					return (refreshed, back.error("temporarily_unavailable")).into_response();
				}
				return (refreshed, redirect(&asked.confirm_url())).into_response();
			}
			Decision::Refused => {
				tracing::info!(client_id = %client.client_id, user_id = %user, max_age, "relying party: authorize refused, the confirmation trip did not confirm");
				return (refreshed, back.error("access_denied")).into_response();
			}
		}
	}
	let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
	let requester = Requester {
		upstream_family: &upstream_family,
		auth_time: confirmed,
		client_ip: &ip,
		user_agent,
	};
	let answer = match relying_parties.issue_code(&client, redirect_uri, code_challenge, user, token_version, requester).await {
		Ok(code) => back.with(&[("code", &code)]),
		Err(err) => {
			tracing::error!(%err, "relying party: code store failed at authorize");
			back.error("temporarily_unavailable")
		}
	};
	(refreshed, answer).into_response()
}

/// Longest client id worth a lookup; registered ids are far shorter.
const MAX_CLIENT_ID_LEN: usize = 64;

/// `GET /auth/clients/{client_id}` (publicly `/api/auth/clients/{client_id}`) — the name of
/// the app a confirmation is for, so the confirmation page can say who asks. Read from the
/// registry, never from the request: a name taken from the query would let any link
/// dress the platform's page up as any app. Public, no credentials, cacheable; a client
/// `/auth/authorize` would not serve (unknown, disabled, of a closed scope) is the same 404.
/// `display_name` may be empty: the scope never set one.
pub async fn client_name(State(st): State<WebState>, Path(client_id): Path<String>) -> Response {
	let st = &st.inner;
	let unknown = || {
		(
			StatusCode::NOT_FOUND,
			[(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"))],
			Json(serde_json::json!({ "error": "unknown_client" })),
		)
			.into_response()
	};
	let Some(relying_parties) = st.relying_parties.as_ref() else {
		return unknown();
	};
	if client_id.len() > MAX_CLIENT_ID_LEN {
		return unknown();
	}
	match relying_parties.signing_in(&client_id).await {
		Ok(Some(client)) => (
			[(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"))],
			Json(serde_json::json!({ "client_id": client.client_id, "display_name": client.display_name })),
		)
			.into_response(),
		Ok(None) => unknown(),
		Err(err) => {
			tracing::error!(%err, "relying party: registry unreadable for a client name");
			(StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "unavailable" }))).into_response()
		}
	}
}

/// The browser's `evinvest.ltd` session and the refresh family behind it, or `None` when
/// there is no session to act on. The family is checked first-hand (`live_family_of`):
/// handing out a new credential on a session revoked elsewhere is exactly what the
/// revocation was meant to stop.
async fn live_session(st: &super::Inner, session_id: &str) -> color_eyre::Result<Option<(Fresh, String)>> {
	let Some(fresh) = st.sessions.fresh(session_id, &st.auth).await? else {
		return Ok(None);
	};
	Ok(live_family_of(st, session_id).await?.map(|family| (fresh, family)))
}

/// The client's redirect_uri, once it is known to be registered.
struct Back<'a> {
	redirect_uri: &'a str,
	state: Option<&'a str>,
}

impl Back<'_> {
	fn error(&self, error: &str) -> Response {
		self.with(&[("error", error)])
	}

	fn with(&self, params: &[(&str, &str)]) -> Response {
		let mut query = form_urlencoded::Serializer::new(String::new());
		for (key, value) in params {
			query.append_pair(key, value);
		}
		if let Some(state) = self.state {
			query.append_pair("state", state);
		}
		let sep = if self.redirect_uri.contains('?') { '&' } else { '?' };
		redirect(&format!("{}{sep}{}", self.redirect_uri, query.finish()))
	}
}

/// The authorize request as this route understood it.
struct Asked<'a> {
	client_id: &'a str,
	redirect_uri: &'a str,
	state: Option<&'a str>,
	code_challenge: &'a str,
	max_age: Option<u64>,
}

impl Asked<'_> {
	/// The path back to this exact request. Rebuilt from the parsed parameters, never
	/// copied from the raw query, so nothing the caller added rides along.
	fn path(&self) -> String {
		let mut back = form_urlencoded::Serializer::new(String::new());
		back.append_pair("client_id", self.client_id)
			.append_pair("redirect_uri", self.redirect_uri)
			.append_pair("response_type", "code");
		if let Some(state) = self.state {
			back.append_pair("state", state);
		}
		back.append_pair("code_challenge", self.code_challenge).append_pair("code_challenge_method", "S256");
		if let Some(max_age) = self.max_age {
			back.append_pair("max_age", &max_age.to_string());
		}
		format!("{PUBLIC_PATH}?{}", back.finish())
	}

	/// The ordinary login, coming back here with `max_age`. A new sign-in is no
	/// confirmation — a provider can complete it without the person doing anything — so
	/// `max_age=0` still sends the new session to confirm on the way back.
	fn login_url(&self) -> String {
		let login = form_urlencoded::Serializer::new(String::new()).append_pair("returnTo", &self.path()).finish();
		format!("{LOGIN_PATH}?{login}")
	}

	fn confirm_url(&self) -> String {
		let confirm = form_urlencoded::Serializer::new(String::new()).append_pair("return_to", &self.path()).finish();
		format!("{CONFIRM_PATH}?{confirm}")
	}
}

/// Digits only: no sign, no space, no fraction — OIDC's non-negative integer.
fn parse_max_age(raw: &str) -> Option<u64> {
	if raw.is_empty() || raw.len() > MAX_AGE_DIGITS || !raw.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	raw.parse().ok()
}

/// The confirmation trip of one session, for one client and one authorize request (its
/// PKCE challenge): what the browser that comes back must match.
pub fn trip_key(session_id: &str, client_id: &str, code_challenge: &str) -> String {
	format!("{session_id}:{client_id}:{code_challenge}")
}

#[derive(Debug, Eq, PartialEq)]
enum Decision {
	/// The session meets `max_age` by itself: a code, without `auth_time`.
	Code,
	/// Back from a trip that moved `auth_time` after it began: a code carrying it.
	Confirmed(u64),
	/// Send the person to confirm it is them, and remember the trip.
	Confirm,
	/// Back from a trip that confirmed nothing: refused, never sent round again.
	Refused,
}

/// What `max_age` makes of a session last authenticated at `auth_time`, given the trip
/// this request began at `started` (taken, so `None` when there was none). A session
/// with no `auth_time` predates the claim and meets no `max_age`; `max_age=0` is met by
/// no session, only by a trip.
fn decide(max_age: u64, auth_time: Option<u64>, started: Option<i64>, now: i64) -> Decision {
	let at = auth_time.and_then(|at| i64::try_from(at).ok());
	if let Some(started) = started {
		return match (auth_time, at) {
			(Some(confirmed), Some(at)) if at > started && at <= now.saturating_add(CLOCK_SKEW_SECS) => Decision::Confirmed(confirmed),
			_ => Decision::Refused,
		};
	}
	let limit = i64::try_from(max_age).unwrap_or(i64::MAX);
	match at {
		Some(at) if max_age > 0 && now.saturating_sub(at) <= limit => Decision::Code,
		_ => Decision::Confirm,
	}
}

/// A 302 that no cache keeps and no Referer repeats: the Location carries a one-time
/// code, and the page it lands on must not learn it from this hop either.
fn redirect(location: &str) -> Response {
	let Ok(location) = HeaderValue::from_str(location) else {
		return page(StatusCode::BAD_REQUEST, "This sign-in link is not valid.");
	};
	(
		StatusCode::FOUND,
		[
			(header::LOCATION, location),
			(header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
			(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
		],
	)
		.into_response()
}

/// An error page on THIS origin. The text is fixed: nothing from the request is echoed.
fn page(status: StatusCode, message: &'static str) -> Response {
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign-in</title></head>\
		 <body><main><h1>Sign-in could not continue</h1><p>{message}</p><p><a href=\"/\">Go to evinvest.ltd</a></p></main></body></html>"
	);
	// Never framed: a page on this origin that a client could embed is a page it could
	// dress up. No Referer either — the request URL carries the client's parameters.
	(
		status,
		[
			(header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
			(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
			(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'")),
		],
		Html(body),
	)
		.into_response()
}

#[cfg(test)]
mod tests {
	use super::*;

	const NOW: i64 = 1_800_000_000;

	#[test]
	fn max_age_is_a_plain_non_negative_integer() {
		assert_eq!(parse_max_age("0"), Some(0));
		assert_eq!(parse_max_age("120"), Some(120));
		assert_eq!(parse_max_age("9999999999"), Some(9_999_999_999));
		for bad in ["", "-1", "+1", " 1", "1.5", "1e3", "12345678901", "0x10"] {
			assert_eq!(parse_max_age(bad), None, "{bad:?}");
		}
	}

	#[test]
	fn only_a_trip_that_moved_auth_time_confirms() {
		let at = |age: i64| Some(u64::try_from(NOW - age).unwrap());
		// No trip yet.
		assert_eq!(decide(300, at(300), None, NOW), Decision::Code);
		assert_eq!(decide(300, at(301), None, NOW), Decision::Confirm);
		assert_eq!(decide(0, at(0), None, NOW), Decision::Confirm, "max_age=0 asks even a session authenticated this second");
		assert_eq!(decide(3600, None, None, NOW), Decision::Confirm, "no auth_time meets no max_age");
		assert_eq!(decide(u64::MAX, at(10_000), None, NOW), Decision::Code);
		// Back from a trip that began 20 s ago.
		let started = Some(NOW - 20);
		assert_eq!(decide(0, at(5), started, NOW), Decision::Confirmed(u64::try_from(NOW - 5).unwrap()));
		assert_eq!(decide(0, at(20), started, NOW), Decision::Refused, "moved no later than the trip began");
		assert_eq!(decide(0, at(600), started, NOW), Decision::Refused, "dismissed: the session is as it was");
		assert_eq!(decide(3600, at(600), started, NOW), Decision::Refused, "a trip is answered by a confirmation, not by max_age");
		assert_eq!(decide(0, None, started, NOW), Decision::Refused);
		assert_eq!(decide(0, at(-30), started, NOW), Decision::Confirmed(u64::try_from(NOW + 30).unwrap()), "honest drift");
		assert_eq!(decide(0, at(-31), started, NOW), Decision::Refused, "dated ahead of any honest clock");
	}
}
