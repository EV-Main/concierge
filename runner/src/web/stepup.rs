//! Step-up bound to ONE operation, asked from a trusted page of ours (`/auth/stepup/*`,
//! publicly `/api/auth/stepup/*`).
//!
//! The money plane's wallet runs inside the page of a host that is not `PUBLIC_ORIGIN`
//! (the SA panel, the invest cabinet). Re-authentication (`web::reauth`) cannot serve it:
//! it is `PUBLIC_ORIGIN`-only, and what it yields is a fresher session, which proves
//! nothing about WHICH operation the person agreed to. Here a ceremony is opened for an
//! `intent_hash` the bank computed, kept on THIS side with the account and the asking page,
//! and a passkey assertion or a mailed code that closes it yields a proof for exactly that
//! hash (`evconcierge_auth::stepup`). The session is not touched: `auth_time` stays, and no
//! session cookie is set but the rotation a plain session read owes the browser.
//!
//! The surface is closed three ways. Not mounted at all unless `STEPUP_PROOF_ORIGINS` names
//! an origin. Answers only to those exact origins (`Origin`, never a pattern), from a
//! request the browser itself marks `Sec-Fetch-Site: same-origin|same-site`, carrying JSON
//! (which forces a preflight, the CORS layer's `Max-Age` 60). And it takes no password:
//! the methods are a passkey and a mailed code, and nothing else parses.
//!
//! There is no CSRF token here, by necessity: the double-submit cookie is `__Host-` bound
//! to `PUBLIC_ORIGIN`, which a script on another host can neither read nor set. The
//! exact-origin check, the fetch metadata and the JSON-only body stand in for it; a
//! sibling subdomain that is not listed (a takeover, a rogue) fails the first of them.
//!
//! A ceremony lives in process, like every other here: one that lands on another replica
//! fails and is begun again.

use std::{
	collections::HashMap,
	time::{Duration, Instant},
};

use axum::{
	Extension, Json,
	extract::{Request, State},
	http::{HeaderMap, HeaderValue, Method, StatusCode, header},
	middleware::Next,
	response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use color_eyre::eyre::{Context, bail, ensure};
use domain::users::UserId;
use evconcierge_auth::stepup::{self, StepupMethod, parse_intent_hash};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use webauthn_rs::{
	Webauthn,
	prelude::{Passkey, PasskeyAuthentication, PublicKeyCredential, Url},
};

use crate::{
	infrastructure::email::templates::breaks_or_hides,
	notification::RateLimiter,
	web::{
		Inner, WebState, now_secs,
		passkey::{base64url, expired, rejected},
		reauth::{eligible_passkeys, verified_address},
		routes::ClientIp,
		sign_in::{Answered, Halt, Refusal, Signed, code_refusal, human, internal, require_live, sent, signed_in_read},
	},
};

/// A ceremony and the proof it yields live this long unless configured shorter. The same
/// number is the proof's ceiling (`stepup::MAX_TTL_SECS`).
pub const DEFAULT_TTL_SECS: u64 = stepup::MAX_TTL_SECS;
/// How much the account may ask of these routes: a person confirms an operation once,
/// perhaps twice with a typo.
const ATTEMPT_WINDOW_SECS: u64 = 300;
const ATTEMPTS_PER_WINDOW: u32 = 10;
/// Bounds the store whatever the rate; the oldest ceremony goes first.
const MAX_CEREMONIES: usize = 10_000;
const MAX_SUMMARY_CHARS: usize = 240;
const MAX_AGENT_CHARS: usize = 200;
/// How long a browser may reuse a preflight. Short: a listing withdrawn from the flag
/// should not outlive a deploy by a cached approval.
const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(60);

/// What the composition root hands the web surface; `None` there means "not mounted".
pub struct StepupDeps {
	/// The exact origins that may ask, as [`parse_origins`] returns them.
	pub origins: Vec<String>,
	/// Lifetime of a ceremony and of the proof it yields, capped at the proof ceiling.
	pub ttl_secs: u64,
}

/// Read and check `STEPUP_PROOF_ORIGINS`. Every entry is a bare origin, written the way a
/// browser sends it, never a pattern. In production each must also be `https` and either
/// `PUBLIC_ORIGIN` or a host under it — the passkey's relying party is `PUBLIC_ORIGIN`'s
/// host, so an origin outside could not run a ceremony anyway, and listing one would only
/// widen who may ask for a mail.
pub fn parse_origins(raw: &[String], public_origin: &str, production: bool) -> color_eyre::Result<Vec<String>> {
	let public = Url::parse(public_origin).context("PUBLIC_ORIGIN is not a URL")?;
	let public_host = public.host_str().ok_or_else(|| color_eyre::eyre::eyre!("PUBLIC_ORIGIN has no host"))?.to_owned();
	let mut origins = Vec::new();
	for entry in raw.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
		ensure!(!entry.contains('*'), "STEPUP_PROOF_ORIGINS entry {entry:?}: a pattern is never accepted");
		let url = Url::parse(entry).with_context(|| format!("STEPUP_PROOF_ORIGINS entry {entry:?} is not an origin"))?;
		ensure!(
			url.origin().ascii_serialization() == entry,
			"STEPUP_PROOF_ORIGINS entry {entry:?} is not a bare origin (scheme://host[:port], no path, no trailing slash)"
		);
		if production {
			ensure!(url.scheme() == "https", "STEPUP_PROOF_ORIGINS entry {entry:?} must be https in production");
			let host = url.host_str().unwrap_or_default();
			if host != public_host && !host.ends_with(&format!(".{public_host}")) {
				bail!("STEPUP_PROOF_ORIGINS entry {entry:?} is outside {public_host}");
			}
		}
		if !origins.iter().any(|o| o == entry) {
			origins.push(entry.to_owned());
		}
	}
	Ok(origins)
}

enum Kind {
	Passkey(Box<PasskeyAuthentication>),
	Email,
}

struct Ceremony {
	user: UserId,
	intent_hash: [u8; 32],
	/// The page that asked, from its `Origin` header. The second half must come from it.
	origin: String,
	born: Instant,
	kind: Kind,
}

/// The state behind the routes. Present only where the flag lists an origin.
pub(super) struct Stepup {
	origins: Vec<String>,
	/// Relying party `PUBLIC_ORIGIN`'s host; the origins accepted are `PUBLIC_ORIGIN` and
	/// the listed ones, exactly — not the scope registry, which is wider and moves.
	webauthn: Webauthn,
	ttl: Duration,
	open: Mutex<HashMap<String, Ceremony>>,
	attempts: RateLimiter,
}

impl Stepup {
	pub(super) fn new(deps: StepupDeps, public_origin: &str) -> color_eyre::Result<Self> {
		let webauthn = super::passkey::verifier(public_origin, deps.origins.iter().map(String::as_str))?;
		Ok(Self {
			ttl: Duration::from_secs(deps.ttl_secs.clamp(1, stepup::MAX_TTL_SECS)),
			origins: deps.origins,
			webauthn,
			open: Mutex::new(HashMap::new()),
			attempts: RateLimiter::new(Duration::from_secs(ATTEMPT_WINDOW_SECS), ATTEMPTS_PER_WINDOW),
		})
	}

	pub(super) fn cors(&self) -> CorsLayer {
		let origins = self.origins.clone();
		CorsLayer::new()
			.allow_origin(AllowOrigin::predicate(move |origin, _| origin.to_str().is_ok_and(|o| origins.iter().any(|allowed| allowed == o))))
			.allow_credentials(true)
			.allow_methods([Method::POST])
			.allow_headers([header::CONTENT_TYPE])
			.max_age(PREFLIGHT_MAX_AGE)
	}

	fn ttl_secs(&self) -> u64 {
		self.ttl.as_secs()
	}

	/// Keep a new ceremony and name it. An account has one email ceremony at a time: the
	/// code it mails supersedes the previous one, so an older ceremony would otherwise
	/// accept a code that was mailed for a different operation.
	async fn begin(&self, ceremony: Ceremony) -> (String, i64) {
		let id = super::random_token(24);
		let expires_at = now_secs() + self.ttl_secs() as i64;
		let mut open = self.open.lock().await;
		open.retain(|_, c| c.born.elapsed() <= self.ttl);
		if matches!(ceremony.kind, Kind::Email) {
			open.retain(|_, c| !(c.user == ceremony.user && matches!(c.kind, Kind::Email)));
		}
		if open.len() >= MAX_CEREMONIES
			&& let Some(oldest) = open.iter().min_by_key(|(_, c)| c.born).map(|(k, _)| k.clone())
		{
			open.remove(&oldest);
		}
		open.insert(id.clone(), ceremony);
		(id, expires_at)
	}

	/// The ceremony, spent: a second presentation finds nothing. `None` when it is unknown or
	/// has outlived its lifetime.
	async fn take(&self, id: &str) -> Option<Ceremony> {
		let ceremony = self.open.lock().await.remove(id)?;
		(ceremony.born.elapsed() <= self.ttl).then_some(ceremony)
	}

	/// An email ceremony, left in place: a mistyped code is not the end of it (the code's own
	/// five guesses are).
	async fn email(&self, id: &str) -> Option<(UserId, [u8; 32], String)> {
		let mut open = self.open.lock().await;
		let alive = open.get(id).is_some_and(|c| c.born.elapsed() <= self.ttl);
		if !alive {
			open.remove(id);
			return None;
		}
		let ceremony = open.get(id)?;
		matches!(ceremony.kind, Kind::Email).then(|| (ceremony.user, ceremony.intent_hash, ceremony.origin.clone()))
	}

	async fn discard(&self, id: &str) {
		self.open.lock().await.remove(id);
	}
}

/// The caller's `Origin`, once [`guard`] has found it on the list.
#[derive(Clone)]
pub struct Asked(String);

fn fetch_site_ok(headers: &HeaderMap) -> bool {
	headers
		.get("sec-fetch-site")
		.and_then(|v| v.to_str().ok())
		.is_some_and(|v| matches!(v, "same-origin" | "same-site"))
}

fn json_body(headers: &HeaderMap) -> bool {
	headers
		.get(header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.is_some_and(|v| v.split(';').next().is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json")))
}

/// Everything that is decided before the body is read, for every route here. Layered INSIDE
/// the CORS layer, so a preflight never reaches it.
pub(super) async fn guard(State(st): State<WebState>, mut request: Request, next: Next) -> Response {
	let Some(stepup) = st.inner.stepup.as_ref() else {
		return StatusCode::NOT_FOUND.into_response();
	};
	let headers = request.headers();
	let origin = headers
		.get(header::ORIGIN)
		.and_then(|v| v.to_str().ok())
		.filter(|o| stepup.origins.iter().any(|allowed| allowed == o))
		.map(str::to_owned);
	let refusal = match origin {
		None => Some(Refusal::new(StatusCode::FORBIDDEN, "origin")),
		Some(_) if !fetch_site_ok(headers) => Some(Refusal::new(StatusCode::FORBIDDEN, "fetch_site")),
		Some(_) if !json_body(headers) => Some(Refusal::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type")),
		Some(origin) => {
			request.extensions_mut().insert(Asked(origin));
			None
		}
	};
	let mut response = match refusal {
		Some(refusal) => refusal.into_response(),
		None => next.run(request).await,
	};
	// A proof is a bearer credential for one operation: nothing between here and the page
	// may keep a copy.
	response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
	response
}

fn spend(sp: &Stepup, user: UserId) -> Result<(), Refusal> {
	match sp.attempts.check(&user.to_string()) {
		true => Ok(()),
		false => Err(Refusal::new(StatusCode::TOO_MANY_REQUESTS, "throttled")),
	}
}

fn invalid(code: &'static str) -> Refusal {
	Refusal::new(StatusCode::BAD_REQUEST, code)
}

/// The signed-in account of a request that carries no CSRF token (see the module note):
/// gated as every session read is, and with the refresh family checked first-hand, as
/// the routes that plant a credential do — a session revoked elsewhere must not vouch
/// for an operation.
async fn session(st: &Inner, jar: &CookieJar) -> Result<Signed, Halt> {
	let signed = signed_in_read(st, jar).await?;
	require_live(st, jar, signed).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionsBody {
	/// 64 lowercase hex characters: the bank's hash of the operation it stored.
	intent_hash: String,
	/// `passkey` or `email_code`. Read as text so that any other word, a password included,
	/// is told `invalid_method` rather than a parser's prose.
	method: String,
	/// For `email_code` only: what the page says the operation is, quoted in the mail as the
	/// page's own words.
	#[serde(default)]
	summary: Option<String>,
	#[serde(default)]
	turnstile_token: String,
}

/// `POST /auth/stepup/options` — open a ceremony for one operation.
pub async fn options(State(st): State<WebState>, Extension(Asked(origin)): Extension<Asked>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<OptionsBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = session(st, &jar).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sp = st.stepup.as_ref().ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "not_found"))?;
		let intent_hash = parse_intent_hash(&body.intent_hash).ok_or_else(|| invalid("invalid_intent"))?;
		let method = match body.method.as_str() {
			"passkey" => StepupMethod::Passkey,
			"email_code" => StepupMethod::EmailCode,
			_ => return Err(invalid("invalid_method")),
		};
		spend(sp, user.id())?;
		match method {
			StepupMethod::Passkey => begin_passkey(st, sp, &jar, user.id(), intent_hash, origin).await,
			StepupMethod::EmailCode => {
				verified_address(&user)?;
				let summary = clean_summary(body.summary.as_deref())?;
				human(st, &ip, &body.turnstile_token).await?;
				let now = now_secs();
				let context = json!({
					"origin": origin,
					"summary": summary,
					"reference": &body.intent_hash[..8],
					"client_ip": ip.0,
					"user_agent": headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default().chars().take(MAX_AGENT_CHARS).collect::<String>(),
					"requested_at": now,
				});
				let issue = st
					.credentials
					.issue_stepup_code(user.id(), context, sp.ttl_secs() as i64, now)
					.await
					.map_err(|e| internal("stepup: code not issued", e))?;
				// Answers Ok only for a code that was queued; every other issue is a refusal.
				sent(st, issue).await.map(|_| ())?;
				let (ceremony_id, expires_at) = sp
					.begin(Ceremony {
						user: user.id(),
						intent_hash,
						origin,
						born: Instant::now(),
						kind: Kind::Email,
					})
					.await;
				Ok(Json(json!({ "ceremony_id": ceremony_id, "method": "email_code", "expires_at": expires_at })))
			}
		}
	}
	.await;
	Ok((jar, answer))
}

/// What the page says the operation is, kept to one short line of printable text: it is
/// quoted in a mail, and the mail's own lines must not be forgeable through it.
fn clean_summary(raw: Option<&str>) -> Result<String, Refusal> {
	let summary = raw.map(str::trim).unwrap_or_default();
	if summary.is_empty() || summary.chars().count() > MAX_SUMMARY_CHARS || summary.chars().any(breaks_or_hides) {
		return Err(invalid("invalid_summary"));
	}
	Ok(summary.to_owned())
}

async fn begin_passkey(st: &Inner, sp: &Stepup, jar: &CookieJar, user: UserId, intent_hash: [u8; 32], origin: String) -> Result<Json<Value>, Refusal> {
	let rows = eligible_passkeys(st, jar, user).await?;
	let passkeys = rows
		.into_iter()
		.map(|row| serde_json::from_value::<Passkey>(row.passkey))
		.collect::<Result<Vec<_>, _>>()
		.map_err(|e| internal("stepup: a stored passkey does not parse", e))?;
	if passkeys.is_empty() {
		return Err(invalid("no_passkey"));
	}
	let (options, state) = sp.webauthn.start_passkey_authentication(&passkeys).map_err(|e| internal("stepup: assertion not begun", e))?;
	let (ceremony_id, expires_at) = sp
		.begin(Ceremony {
			user,
			intent_hash,
			origin,
			born: Instant::now(),
			kind: Kind::Passkey(Box::new(state)),
		})
		.await;
	Ok(Json(json!({ "ceremony_id": ceremony_id, "method": "passkey", "options": options, "expires_at": expires_at })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
	ceremony_id: String,
	/// The authenticator's assertion, for a passkey ceremony.
	#[serde(default)]
	response: Option<PublicKeyCredential>,
	/// The mailed code, for an email ceremony.
	#[serde(default)]
	code: Option<String>,
}

/// `POST /auth/stepup/verify` — close the ceremony and answer the proof for its operation.
pub async fn verify(State(st): State<WebState>, Extension(Asked(origin)): Extension<Asked>, jar: CookieJar, Json(body): Json<VerifyBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = session(st, &jar).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sp = st.stepup.as_ref().ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "not_found"))?;
		spend(sp, user.id())?;
		match (body.response, body.code) {
			(Some(credential), None) => verify_passkey(st, sp, &jar, user.id(), &origin, &body.ceremony_id, &credential).await,
			(None, Some(code)) => verify_code(st, sp, user.id(), &origin, &body.ceremony_id, &code).await,
			_ => Err(invalid("invalid_request")),
		}
	}
	.await;
	Ok((jar, answer))
}

async fn verify_passkey(st: &Inner, sp: &Stepup, jar: &CookieJar, user: UserId, origin: &str, ceremony_id: &str, credential: &PublicKeyCredential) -> Result<Json<Value>, Refusal> {
	let ceremony = sp.take(ceremony_id).await.ok_or_else(expired)?;
	let Kind::Passkey(state) = ceremony.kind else {
		return Err(expired());
	};
	// The ceremony is the account's and the page's that began it; neither a sibling page nor
	// another account of the same browser can finish it.
	if ceremony.user != user || ceremony.origin != origin {
		return Err(expired());
	}
	assert_made_on(credential, &ceremony.origin)?;
	let result = sp.webauthn.finish_passkey_authentication(credential, &state).map_err(|e| {
		tracing::info!(error = %e, "stepup: assertion refused");
		rejected()
	})?;
	let credential_id = base64url(result.cred_id());
	// Checked again here, not only when the ceremony began: a key planted between the two
	// must not count (the rule `reauth` keeps).
	let row = eligible_passkeys(st, jar, user)
		.await?
		.into_iter()
		.find(|row| row.credential_id == credential_id)
		.ok_or_else(rejected)?;
	let mut passkey: Passkey = serde_json::from_value(row.passkey).map_err(|e| internal("stepup: a stored passkey does not parse", e))?;
	passkey.update_credential(&result);
	let updated = serde_json::to_value(&passkey).map_err(|e| internal("stepup: passkey not serialized", e))?;
	st.credentials
		.passkey_used(&credential_id, updated, now_secs())
		.await
		.map_err(|e| internal("stepup: passkey use not recorded", e))?;
	proof(st, sp, user, &ceremony.intent_hash, &ceremony.origin, StepupMethod::Passkey)
}

/// The assertion's own `clientDataJSON` names the page it was made on. The verifier accepts
/// any listed origin, so without this a page could finish a ceremony with an assertion made
/// on another listed page; and an assertion made inside a cross-origin frame is refused.
fn assert_made_on(credential: &PublicKeyCredential, origin: &str) -> Result<(), Refusal> {
	let client_data: Value = serde_json::from_slice(credential.response.client_data_json.as_ref()).map_err(|_| rejected())?;
	let same_page = client_data.get("origin").and_then(Value::as_str) == Some(origin);
	let assertion = client_data.get("type").and_then(Value::as_str) == Some("webauthn.get");
	let framed = client_data.get("crossOrigin").and_then(Value::as_bool).unwrap_or(false);
	match same_page && assertion && !framed {
		true => Ok(()),
		false => Err(rejected()),
	}
}

async fn verify_code(st: &Inner, sp: &Stepup, user: UserId, origin: &str, ceremony_id: &str, code: &str) -> Result<Json<Value>, Refusal> {
	let (owner, intent_hash, asked_from) = sp.email(ceremony_id).await.ok_or_else(expired)?;
	if owner != user || asked_from != origin {
		return Err(expired());
	}
	match st
		.credentials
		.redeem_stepup_code(user, code, now_secs())
		.await
		.map_err(|e| internal("stepup: code not redeemed", e))?
	{
		Ok(()) => {
			sp.discard(ceremony_id).await;
			proof(st, sp, user, &intent_hash, &asked_from, StepupMethod::EmailCode)
		}
		Err(refusal) => {
			use crate::ports::CodeRefusal;
			// A burned or lapsed code leaves nothing for the ceremony to wait for.
			if matches!(refusal, CodeRefusal::Exhausted | CodeRefusal::Expired | CodeRefusal::Missing) {
				sp.discard(ceremony_id).await;
			}
			Err(code_refusal(refusal))
		}
	}
}

fn proof(st: &Inner, sp: &Stepup, user: UserId, intent_hash: &[u8; 32], origin: &str, method: StepupMethod) -> Result<Json<Value>, Refusal> {
	let minted = st
		.auth
		.mint_stepup_proof(&user.to_string(), intent_hash, method, origin, sp.ttl_secs())
		.map_err(|e| internal("stepup: proof not minted", e))?;
	tracing::info!(%user, origin, method = method.as_str(), jti = %minted.jti, "step-up proof issued");
	Ok(Json(json!({ "proof": minted.token, "method": method.as_str(), "expires_at": minted.exp })))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(raw: &[&str], production: bool) -> color_eyre::Result<Vec<String>> {
		parse_origins(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "https://evinvest.ltd", production)
	}

	#[test]
	fn the_flag_takes_bare_https_origins_under_the_site_and_nothing_else() {
		assert_eq!(parse(&[], true).unwrap(), Vec::<String>::new());
		assert_eq!(
			parse(
				&["https://invest.evinvest.ltd", " https://sa.evinvest.ltd ", "https://invest.evinvest.ltd", "https://evinvest.ltd"],
				true
			)
			.unwrap(),
			["https://invest.evinvest.ltd", "https://sa.evinvest.ltd", "https://evinvest.ltd"]
		);
		for bad in [
			"*",
			"https://*.evinvest.ltd",
			"https://invest.evinvest.ltd/",
			"https://invest.evinvest.ltd/wallet",
			"http://invest.evinvest.ltd",
			"https://evinvest.ltd.evil.example",
			"https://notevinvest.ltd",
			"https://elsewhere.example",
			"invest.evinvest.ltd",
			"https://INVEST.evinvest.ltd",
			"null",
		] {
			assert!(parse(&[bad], true).is_err(), "{bad:?} must be refused in production");
		}
	}

	#[test]
	fn outside_production_the_shape_is_still_checked_but_http_and_other_hosts_pass() {
		assert_eq!(parse(&["http://localhost:3000"], false).unwrap(), ["http://localhost:3000"]);
		for bad in ["*", "http://localhost:3000/", "http://localhost:3000/x"] {
			assert!(parse(&[bad], false).is_err(), "{bad:?}");
		}
	}

	#[test]
	fn a_summary_is_one_short_printable_line() {
		assert!(clean_summary(Some("Send 5 USDT to TXyz")).is_ok());
		for bad in [None, Some(""), Some("   "), Some("a\nb"), Some("a\u{202e}b"), Some(&"x".repeat(MAX_SUMMARY_CHARS + 1))] {
			assert!(clean_summary(bad).is_err(), "{bad:?}");
		}
	}

	#[test]
	fn only_a_browser_marked_same_origin_or_same_site_passes() {
		let with = |v: Option<&str>| {
			let mut h = HeaderMap::new();
			if let Some(v) = v {
				h.insert("sec-fetch-site", HeaderValue::from_str(v).unwrap());
			}
			fetch_site_ok(&h)
		};
		assert!(with(Some("same-origin")) && with(Some("same-site")));
		assert!(!with(Some("cross-site")) && !with(Some("none")) && !with(Some("")) && !with(None));
	}

	#[test]
	fn the_body_must_be_json() {
		let with = |v: &str| {
			let mut h = HeaderMap::new();
			h.insert(header::CONTENT_TYPE, HeaderValue::from_str(v).unwrap());
			json_body(&h)
		};
		assert!(with("application/json") && with("application/json; charset=utf-8") && with("Application/JSON"));
		assert!(!with("text/plain") && !with("application/x-www-form-urlencoded") && !with("multipart/form-data") && !with("application/jsonp"));
		assert!(!json_body(&HeaderMap::new()));
	}
}
