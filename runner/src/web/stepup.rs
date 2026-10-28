//! Step-up bound to ONE operation, asked from a trusted page of ours (`/auth/stepup/*`,
//! publicly `/api/auth/stepup/*`).
//!
//! The money plane's wallet runs inside the page of a host that is not `PUBLIC_ORIGIN`
//! (the SA panel, the invest cabinet). Re-authentication (`web::reauth`) cannot serve it:
//! it is `PUBLIC_ORIGIN`-only, and what it yields is a fresher session, which proves
//! nothing about WHICH operation the person agreed to. Here a ceremony is opened for an
//! `intent_hash` the bank computed, kept on THIS side with the account and the asking page,
//! and an answer of one of the account's second factors that closes it yields a proof for
//! exactly that hash (`evconcierge_auth::stepup`). The session is not touched: `auth_time`
//! stays, and no session cookie is set but the rotation a plain session read owes the browser.
//!
//! The surface is closed three ways. Not mounted at all unless `STEPUP_PROOF_ORIGINS` names
//! an origin. Answers only to those exact origins (`Origin`, never a pattern), from a
//! request the browser itself marks `Sec-Fetch-Site: same-origin|same-site`, carrying JSON
//! (which forces a preflight, the CORS layer's `Max-Age` 60). And it takes no password:
//! a second factor's answer is the only thing that parses.
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
use evconcierge_auth::stepup::{self, Aal, parse_intent_hash};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;
use webauthn_rs::prelude::Url;

use crate::{
	notification::RateLimiter,
	ports::Attempt,
	web::{
		Inner, WebState, now_secs, second_factor,
		sign_in::{Answered, Body, Halt, Refusal, Signed, internal, require_live, signed_in_read},
	},
};

/// A ceremony and the proof it yields live this long unless configured shorter. The same
/// number is the proof's ceiling (`stepup::MAX_TTL_SECS`).
pub const DEFAULT_TTL_SECS: u64 = stepup::MAX_TTL_SECS;
/// How many ceremonies the account may open: a person confirms an operation once, perhaps
/// twice with a typo.
const ATTEMPT_WINDOW_SECS: u64 = 300;
const ATTEMPTS_PER_WINDOW: u32 = 10;
/// Bounds the store whatever the rate; the oldest ceremony goes first.
const MAX_CEREMONIES: usize = 10_000;
/// How many ceremonies one account may hold open. A page that opens them in a loop evicts
/// its own oldest, never anyone else's.
const MAX_OPEN_PER_USER: usize = 3;
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
/// `PUBLIC_ORIGIN` or a host under it — a page outside the site is `cross-site` to this
/// one and fails `Sec-Fetch-Site` anyway, so listing one could only be a mistake.
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
		let host = url.host_str().unwrap_or_default();
		let under_site = host == public_host || host.ends_with(&format!(".{public_host}"));
		if production {
			ensure!(url.scheme() == "https", "STEPUP_PROOF_ORIGINS entry {entry:?} must be https in production");
			// `Url` drops a scheme's default port, so any port still there is not the default.
			ensure!(url.port().is_none(), "STEPUP_PROOF_ORIGINS entry {entry:?} must not name a port in production");
			if !under_site {
				bail!("STEPUP_PROOF_ORIGINS entry {entry:?} is outside {public_host}");
			}
		} else {
			// Outside production a page may run on loopback; anything else must still be the
			// site or under it, so a mistyped host does not quietly become an allowlisted one.
			let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
			ensure!(under_site || loopback, "STEPUP_PROOF_ORIGINS entry {entry:?} is neither loopback nor under {public_host}");
		}
		if !origins.iter().any(|o| o == entry) {
			origins.push(entry.to_owned());
		}
	}
	Ok(origins)
}

struct Ceremony {
	user: UserId,
	intent_hash: [u8; 32],
	/// The page that asked, from its `Origin` header. The second half must come from it.
	origin: String,
	born: Instant,
	/// The account's second factors, each with what its kind holds until the answer.
	pending: Vec<second_factor::Pending>,
}

/// The state behind the routes. Present only where the flag lists an origin.
pub(super) struct Stepup {
	origins: Vec<String>,
	ttl: Duration,
	open: Mutex<HashMap<String, Ceremony>>,
	attempts: RateLimiter,
}

impl Stepup {
	pub(super) fn new(deps: StepupDeps) -> Self {
		Self {
			ttl: Duration::from_secs(deps.ttl_secs.clamp(1, stepup::MAX_TTL_SECS)),
			origins: deps.origins,
			open: Mutex::new(HashMap::new()),
			attempts: RateLimiter::new(Duration::from_secs(ATTEMPT_WINDOW_SECS), ATTEMPTS_PER_WINDOW),
		}
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

	/// Keep a new ceremony and name it.
	async fn begin(&self, ceremony: Ceremony) -> (String, i64) {
		let id = super::random_token(24);
		let expires_at = now_secs() + self.ttl_secs() as i64;
		let mut open = self.open.lock().await;
		open.retain(|_, c| c.born.elapsed() <= self.ttl);
		let mut mine: Vec<(String, Instant)> = open.iter().filter(|(_, c)| c.user == ceremony.user).map(|(k, c)| (k.clone(), c.born)).collect();
		if mine.len() >= MAX_OPEN_PER_USER {
			mine.sort_by_key(|(_, born)| *born);
			for (key, _) in mine.iter().take(mine.len() + 1 - MAX_OPEN_PER_USER) {
				open.remove(key);
			}
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
}

/// The caller's `Origin`, once `guard` has found it on the list.
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
	/// The least assurance the operation asks for: the account's second factors that give
	/// at least this much are offered.
	min_aal: u8,
}

/// `POST /auth/stepup/options` — open a ceremony for one operation.
pub async fn options(State(st): State<WebState>, Extension(Asked(origin)): Extension<Asked>, jar: CookieJar, Body(body): Body<OptionsBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = session(st, &jar).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sp = st.stepup.as_ref().ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "not_found"))?;
		let intent_hash = parse_intent_hash(&body.intent_hash).ok_or_else(|| invalid("invalid_intent"))?;
		let min_aal = Aal::named(body.min_aal).ok_or_else(|| invalid("invalid_aal"))?;
		spend(sp, user.id())?;
		let second_factor::Challenges { offered, pending } = second_factor::challenge(st, user.id(), min_aal).await?;
		let (ceremony_id, expires_at) = sp
			.begin(Ceremony {
				user: user.id(),
				intent_hash,
				origin,
				born: Instant::now(),
				pending,
			})
			.await;
		Ok(Json(json!({ "ceremony_id": ceremony_id, "factors": offered, "expires_at": expires_at })))
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
	ceremony_id: String,
	/// The factor answered.
	factor: Uuid,
	/// The factor's answer, in its kind's shape.
	response: Value,
}

/// `POST /auth/stepup/verify` — close the ceremony and answer the proof for its operation.
/// Not charged: an answer needs a ceremony `options` was charged for, and the account's guard
/// is what bounds the guesses — a budget spent here would end them before it does.
pub async fn verify(State(st): State<WebState>, Extension(Asked(origin)): Extension<Asked>, jar: CookieJar, Body(body): Body<VerifyBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = session(st, &jar).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sp = st.stepup.as_ref().ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "not_found"))?;
		let user = user.id();
		let lapsed = || invalid("ceremony_expired");
		let ceremony = sp.take(&body.ceremony_id).await.ok_or_else(lapsed)?;
		if ceremony.user != user || ceremony.origin != origin {
			return Err(lapsed());
		}
		let (_, kind, pending) = ceremony.pending.into_iter().find(|(id, ..)| *id == body.factor).ok_or_else(lapsed)?;
		match second_factor::answer(st, user, body.factor, pending, body.response).await? {
			Attempt::Accepted(()) => {
				let aal = kind.aal();
				let minted = st
					.auth
					.mint_stepup_proof(&user.to_string(), &ceremony.intent_hash, aal, &ceremony.origin, sp.ttl_secs())
					.map_err(|e| internal("stepup: proof not minted", e))?;
				tracing::info!(%user, origin = ceremony.origin, aal = aal.level(), jti = %minted.jti, "step-up proof issued");
				Ok(Json(json!({ "proof": minted.token, "aal": aal.level(), "expires_at": minted.exp })))
			}
			other => Err(second_factor::refused(&other)),
		}
	}
	.await;
	Ok((jar, answer))
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
			"https://invest.evinvest.ltd:8443",
			"https://invest.evinvest.ltd:443",
			"null",
		] {
			assert!(parse(&[bad], true).is_err(), "{bad:?} must be refused in production");
		}
	}

	#[test]
	fn outside_production_the_shape_is_still_checked_and_only_loopback_or_the_site_passes() {
		assert_eq!(parse(&["http://localhost:3000", "http://127.0.0.1:3000", "http://sa.evinvest.ltd:3000"], false).unwrap().len(), 3);
		for bad in [
			"*",
			"http://localhost:3000/",
			"http://localhost:3000/x",
			"https://elsewhere.example",
			"https://evinvest.ltd.evil.example",
		] {
			assert!(parse(&[bad], false).is_err(), "{bad:?}");
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
