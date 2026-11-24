//! `/auth/cli` — a command-line tool on the person's own computer signs in through their
//! browser (publicly `evinvest.ltd/api/auth/cli`; RFC 8252 with PKCE S256):
//!
//! ```text
//! browser → GET /api/auth/cli?redirect_uri=http://127.0.0.1:<port>/…&state&code_challenge&code_challenge_method=S256
//!         → [no session] the zone sign-in and back → a page with one button
//!         → POST → 303 redirect_uri?code&state
//! tool    → POST /api/auth/cli/token {code, code_verifier} → {session}
//!         → a staff page, `Authorization: Bearer <session>` → `/auth/gate`
//! ```
//!
//! The tool is no registered client: what it gets opens `/auth/gate` alone, and only for an
//! account the gate passes. The session is a family of the account's own
//! (`evconcierge_auth`), not a child of the browser's: signing that browser out leaves it.

use axum::{
	Form, Json,
	extract::{
		Query, State,
		rejection::{FormRejection, JsonRejection, QueryRejection},
	},
	http::{HeaderMap, HeaderValue, StatusCode, header},
	response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use evconcierge_auth::CliRedemption;
use serde::Deserialize;
use serde_json::json;

use crate::{
	relying_party::{CODE_TTL_SECS, is_s256_challenge, s256_challenge},
	web::{
		WebState,
		authorize::{self, Back},
		logout::{STYLE, escape, guarded},
		routes::{ClientIp, CsrfOutcome, NotStaff, clear_session, csrf_outcome_of, is_staff, live_family_of, sign_in_at, staff},
		sign_in::{Refusal, internal},
	},
};

pub const PUBLIC_PATH: &str = "/api/auth/cli";
/// Bounds the redirect and the state so that the way back from a sign-in, percent-encoded,
/// stays within what `safe_return_to` keeps.
const MAX_LEN: usize = 256;

/// What a tool asks for.
#[derive(Deserialize)]
struct Ask {
	redirect_uri: String,
	state: String,
	code_challenge: String,
}

impl Ask {
	fn is_valid(&self) -> bool {
		self.redirect_uri.len() <= MAX_LEN && is_loopback(&self.redirect_uri) && (1..=MAX_LEN).contains(&self.state.len()) && is_s256_challenge(&self.code_challenge)
	}

	/// The path back to this request, rebuilt so that nothing else rides along.
	fn path(&self) -> String {
		let query = form_urlencoded::Serializer::new(String::new())
			.append_pair("redirect_uri", &self.redirect_uri)
			.append_pair("state", &self.state)
			.append_pair("code_challenge", &self.code_challenge)
			.append_pair("code_challenge_method", "S256")
			.finish();
		format!("{PUBLIC_PATH}?{query}")
	}

	fn back(&self, name: &str, value: &str) -> String {
		Back {
			redirect_uri: &self.redirect_uri,
			state: Some(&self.state),
		}
		.url(&[(name, value)])
	}

	fn turned_away(&self, st: &super::Inner, not_staff: NotStaff) -> Response {
		match not_staff {
			NotStaff::SignedOut(jar) => (jar, sign_in_at(st, &self.path())).into_response(),
			NotStaff::Investor(jar) => (jar, authorize::page(StatusCode::FORBIDDEN, "A command-line tool signs in for a staff account only.")).into_response(),
			NotStaff::Unknown(refusal) => refusal.into_response(),
		}
	}
}

#[derive(Deserialize)]
pub struct PageQuery {
	#[serde(flatten)]
	ask: Ask,
	code_challenge_method: String,
	/// Set by a sign-in that failed or was given up. Its value is not read.
	auth_error: Option<String>,
}

#[derive(Deserialize)]
pub struct ConfirmForm {
	#[serde(flatten)]
	ask: Ask,
	csrf: String,
}

#[derive(Deserialize)]
pub struct TokenRequest {
	code: String,
	code_verifier: String,
}

/// `GET /auth/cli` — the button.
pub async fn page(State(st): State<WebState>, jar: CookieJar, query: Result<Query<PageQuery>, QueryRejection>) -> Response {
	let st = &st.inner;
	let Some(Query(q)) = query.ok().filter(|Query(q)| q.code_challenge_method == "S256" && q.ask.is_valid()) else {
		return malformed();
	};
	// Before the session is read, as at `/auth/authorize`: told to the tool, not sent round again.
	if q.auth_error.is_some() {
		return authorize::redirect(&q.ask.back("error", "access_denied"));
	}
	let (jar, user) = match staff(st, jar).await {
		Ok(staff) => staff,
		Err(not_staff) => return q.ask.turned_away(st, not_staff),
	};
	let id = jar.get(&st.cookies.session).expect("staff() read the session it names").value();
	let csrf = match st.sessions.csrf(id).await {
		Ok(Some(csrf)) => csrf,
		Ok(None) => return q.ask.turned_away(st, NotStaff::SignedOut(clear_session(st, jar))),
		Err(e) => return internal("CLI sign-in: web session store failed", e).into_response(),
	};
	let body = format!(
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
		 <meta name=\"color-scheme\" content=\"dark light\"><title>Sign in a command-line tool</title><style>{STYLE}</style></head>\n\
		 <body><main><p class=\"brand\">EV Investment</p><h1>Sign in a command-line tool</h1>\n\
		 <p>A command-line tool on this computer asks to open staff pages as <b>{email}</b>. Continue only if you have just started it yourself.</p>\n\
		 <form method=\"post\" action=\"{PUBLIC_PATH}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
		 <input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect_uri}\"><input type=\"hidden\" name=\"state\" value=\"{state}\">\
		 <input type=\"hidden\" name=\"code_challenge\" value=\"{code_challenge}\">\n\
		 <button type=\"submit\">Sign in</button></form>\n\
		 <a href=\"{cancel}\">Cancel</a></main></body></html>",
		email = escape(user.email().as_str()),
		csrf = escape(&csrf),
		redirect_uri = escape(&q.ask.redirect_uri),
		state = escape(&q.ask.state),
		code_challenge = q.ask.code_challenge,
		cancel = escape(&q.ask.back("error", "access_denied")),
	);
	// The whole scheme and not the one origin: CSP has no source for an IPv6 literal.
	(jar, guarded("http:"), Html(body)).into_response()
}

/// `POST /auth/cli` — the person pressed it: a one-time code for the tool.
pub async fn confirm(State(st): State<WebState>, jar: CookieJar, form: Result<Form<ConfirmForm>, FormRejection>) -> Response {
	let st = &st.inner;
	let Some(Form(ConfirmForm { ask, csrf })) = form.ok().filter(|Form(form)| form.ask.is_valid()) else {
		return malformed();
	};
	match csrf_outcome_of(st, &jar, Some(&csrf)).await {
		Ok(CsrfOutcome::Ok) => {}
		Ok(CsrfOutcome::NoSession) => return ask.turned_away(st, NotStaff::SignedOut(clear_session(st, jar))),
		Ok(CsrfOutcome::Mismatch) => return authorize::page(StatusCode::FORBIDDEN, "This request could not be verified. Please start again from the command-line tool."),
		Err(refusal) => return refusal.into_response(),
	}
	let (jar, user) = match staff(st, jar).await {
		Ok(staff) => staff,
		Err(not_staff) => return ask.turned_away(st, not_staff),
	};
	let id = jar.get(&st.cookies.session).expect("staff() read the session it names").value();
	match live_family_of(st, id).await {
		Ok(Some(_)) => {}
		Ok(None) => return ask.turned_away(st, NotStaff::SignedOut(clear_session(st, jar))),
		Err(e) => return internal("CLI sign-in: refresh family unreadable", e).into_response(),
	}
	match st
		.auth
		.issue_cli_code(&user.id().to_string(), user.token_version(), &ask.code_challenge, CODE_TTL_SECS.unsigned_abs())
		.await
	{
		Ok(code) => {
			tracing::info!(user_id = %user.id(), "CLI sign-in: code issued");
			let headers = [(header::CACHE_CONTROL, "no-store"), (header::REFERRER_POLICY, "no-referrer")];
			(jar, headers, Redirect::to(&ask.back("code", &code))).into_response()
		}
		Err(e) => internal("CLI sign-in: code not issued", e).into_response(),
	}
}

/// `POST /auth/cli/token` — the tool's exchange. One answer for everything wrong with what it
/// sent, an account the gate would refuse by now included.
pub async fn token(State(st): State<WebState>, ClientIp(ip): ClientIp, headers: HeaderMap, body: Result<Json<TokenRequest>, JsonRejection>) -> Result<Response, Refusal> {
	let st = &st.inner;
	let invalid = || Refusal::new(StatusCode::BAD_REQUEST, "invalid_grant");
	let Json(TokenRequest { code, code_verifier }) = body.map_err(|_| invalid())?;
	let user_agent = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
	let redemption = st
		.auth
		.redeem_cli_code(&code, &s256_challenge(&code_verifier), user_agent, ip)
		.await
		.map_err(|e| internal("CLI sign-in: code not redeemed", e))?;
	let session = match redemption {
		CliRedemption::Opened(session) => session,
		CliRedemption::Replayed => {
			tracing::error!("CLI sign-in: code presented twice — the session it opened is ended");
			return Err(invalid());
		}
		CliRedemption::Refused => return Err(invalid()),
	};
	let user = st
		.auth
		.cli_principal(&session, |user| is_staff(&user.role))
		.await
		.map_err(|e| internal("CLI sign-in: account not read", e))?
		.ok_or_else(invalid)?;
	tracing::info!(user_id = %user.user_id, "CLI sign-in: signed in");
	let no_store = [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))];
	Ok((no_store, Json(json!({ "session": session }))).into_response())
}

/// The address literal of this computer, any port (RFC 8252 §7.3); never `localhost`, which a
/// resolver may answer with another host. Compared as text: a URL parser reads `127.1` and
/// `0x7f000001` as the same address.
fn is_loopback(uri: &str) -> bool {
	let Some(rest) = uri.strip_prefix("http://127.0.0.1:").or_else(|| uri.strip_prefix("http://[::1]:")) else {
		return false;
	};
	let Some((port, path)) = rest.split_once('/') else {
		return false;
	};
	port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|port| port != 0) && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
}

fn malformed() -> Response {
	authorize::page(StatusCode::BAD_REQUEST, "This sign-in link is not valid. Please start again from the command-line tool.")
}
