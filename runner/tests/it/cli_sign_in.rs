//! `/auth/cli`: a command-line tool on the person's own computer signs in through the
//! browser and gets a session that opens `/auth/gate` and nothing else.

use axum::{
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header, request::Builder},
};
use common::web::{Browser, ORIGIN, Surface, address, surface};
use concierge::relying_party::s256_challenge;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::common;

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

const REDIRECT: &str = "http://127.0.0.1:49152/callback";
const STATE: &str = "s-t_a.te";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct Page {
	status: StatusCode,
	headers: HeaderMap,
	html: String,
}

impl Page {
	fn location(&self) -> Option<&str> {
		self.headers.get(header::LOCATION).map(|v| v.to_str().unwrap())
	}

	fn hidden(&self, name: &str) -> String {
		let marker = format!("name=\"{name}\" value=\"");
		let start = self.html.find(&marker).unwrap_or_else(|| panic!("no hidden {name} in {}", self.html)) + marker.len();
		self.html[start..].split('"').next().unwrap().to_owned()
	}

	/// The one-time code of the redirect back to the tool.
	fn code(&self) -> String {
		let (back, query) = self.location().expect("a redirect").split_once('?').unwrap();
		assert_eq!((self.status, back), (StatusCode::SEE_OTHER, REDIRECT), "{}", self.html);
		let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes()).into_owned().collect();
		let [(code, value), (state, STATE)] = [&pairs[0], &pairs[1]].map(|(k, v)| (k.as_str(), v.as_str())) else {
			panic!("{pairs:?}");
		};
		assert_eq!((code, state, pairs.len()), ("code", "state", 2));
		value.to_owned()
	}
}

async fn send(fx: &Surface, mut request: Builder, body: Body, browser: &mut Browser) -> Page {
	if !browser.cookies.is_empty() {
		request = request.header(header::COOKIE, browser.header());
	}
	let response = fx.router.clone().oneshot(request.body(body).unwrap()).await.unwrap();
	browser.absorb(response.headers());
	let (status, headers) = (response.status(), response.headers().clone());
	let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
	Page {
		status,
		headers,
		html: String::from_utf8(bytes.to_vec()).unwrap(),
	}
}

fn query(pairs: &[(&str, &str)]) -> String {
	form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

fn ask(redirect_uri: &str) -> String {
	query(&[
		("redirect_uri", redirect_uri),
		("state", STATE),
		("code_challenge", &s256_challenge(VERIFIER)),
		("code_challenge_method", "S256"),
	])
}

async fn page(fx: &Surface, query: &str, browser: &mut Browser) -> Page {
	send(fx, Request::builder().uri(format!("/auth/cli?{query}")), Body::empty(), browser).await
}

async fn press(fx: &Surface, csrf: &str, redirect_uri: &str, browser: &mut Browser) -> Page {
	let request = Request::builder()
		.method(Method::POST)
		.uri("/auth/cli")
		.header(header::ORIGIN, ORIGIN)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
	let form = query(&[("csrf", csrf), ("redirect_uri", redirect_uri), ("state", STATE), ("code_challenge", &s256_challenge(VERIFIER))]);
	send(fx, request, Body::from(form), browser).await
}

async fn code(fx: &Surface, browser: &mut Browser) -> String {
	let shown = page(fx, &ask(REDIRECT), browser).await;
	press(fx, &shown.hidden("csrf"), &shown.hidden("redirect_uri"), browser).await.code()
}

/// What the tool sends, with no browser behind it.
async fn redeem(fx: &Surface, code: &str, verifier: &str) -> (StatusCode, Value) {
	let request = Request::builder()
		.method(Method::POST)
		.uri("/auth/cli/token")
		.header(header::USER_AGENT, "tedi/1.0")
		.header(header::CONTENT_TYPE, "application/json");
	let answer = send(fx, request, Body::from(json!({ "code": code, "code_verifier": verifier }).to_string()), &mut Browser::default()).await;
	(answer.status, serde_json::from_str(&answer.html).unwrap_or(Value::Null))
}

async fn signed_in_tool(fx: &Surface, browser: &mut Browser) -> String {
	let code = code(fx, browser).await;
	let (status, body) = redeem(fx, &code, VERIFIER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["session"].as_str().unwrap().to_owned()
}

fn invalid_grant() -> (StatusCode, Value) {
	(StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" }))
}

/// The request Traefik makes to the gate for a tool's call of a staff page.
async fn gate(fx: &Surface, authorization: &str, browser: &mut Browser) -> Page {
	let request = Request::builder()
		.uri("/auth/gate")
		.header("x-forwarded-method", "GET")
		.header("x-forwarded-proto", "https")
		.header("x-forwarded-host", "evinvest.ltd")
		.header("x-forwarded-uri", "/team/tasks")
		.header(header::AUTHORIZATION, authorization);
	send(fx, request, Body::empty(), browser).await
}

async fn passes(fx: &Surface, session: &str) -> bool {
	let answer = gate(fx, &format!("Bearer {session}"), &mut Browser::default()).await;
	assert!(!answer.headers.contains_key(header::SET_COOKIE), "a tool holds no cookie");
	if answer.status == StatusCode::NO_CONTENT {
		return true;
	}
	assert_refused(&answer);
	false
}

fn assert_refused(answer: &Page) {
	assert_eq!((answer.status, answer.location()), (StatusCode::UNAUTHORIZED, None));
	assert_eq!(answer.headers[header::WWW_AUTHENTICATE], format!("Bearer authorization_uri=\"{ORIGIN}/api/auth/cli\"").as_str());
	assert!(!answer.headers.contains_key("x-auth-user"));
}

async fn signed_in_as(fx: &Surface, role: &str) -> (Browser, String) {
	let email = address(role);
	let mut browser = Browser::default();
	assert_eq!(fx.sign_in_with_code(&email, &mut browser).await.status, StatusCode::OK);
	let id: uuid::Uuid = sqlx::query_scalar("UPDATE users SET role = $1 WHERE email = $2 RETURNING id")
		.bind(role)
		.bind(&email)
		.fetch_one(&fx.db.pool)
		.await
		.unwrap();
	(browser, id.to_string())
}

async fn set(fx: &Surface, user: &str, assignment: &str) {
	sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE users SET {assignment} WHERE id = $1::uuid")))
		.bind(user)
		.execute(&fx.db.pool)
		.await
		.unwrap();
}

async fn sessions(fx: &Surface, browser: &mut Browser) -> Vec<Value> {
	let answer = fx.get("/auth/sessions", browser).await;
	assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
	answer.body["sessions"].as_array().unwrap().clone()
}

/// Overwrite fields of the Redis hash behind a code or a CLI session. `false` (the test
/// returns) when no Redis is configured.
async fn rewrite(handle: &str, fields: &[(&str, i64)]) -> bool {
	let Some(url) = std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("SKIPPED: REDIS_URL unset");
		return false;
	};
	let mut conn = redis::Client::open(url).unwrap().get_multiplexed_async_connection().await.unwrap();
	let () = redis::cmd("HSET").arg(family_key(handle)).arg(fields).query_async(&mut conn).await.unwrap();
	true
}

fn family_key(handle: &str) -> String {
	format!("refresh:fam:{}", handle.split_once('.').unwrap().0)
}

#[tokio::test]
async fn staff_sign_a_tool_in_and_it_passes_the_gate_as_them() {
	let fx = fixture!();
	for role in ["operator", "admin", "owner"] {
		let (mut browser, id) = signed_in_as(&fx, role).await;
		let session = signed_in_tool(&fx, &mut browser).await;
		let answer = gate(&fx, &format!("Bearer {session}"), &mut Browser::default()).await;
		assert_eq!(answer.status, StatusCode::NO_CONTENT, "{role}");
		assert_eq!(answer.headers["x-auth-user"], id.as_str(), "{role}");
		assert!(!answer.headers.contains_key(header::SET_COOKIE), "{role}");
		assert!(passes(&fx, &session).await, "a session is presented again and again");
	}
}

#[tokio::test]
async fn the_page_says_what_signs_in_and_as_whom_and_mints_nothing() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let email = fx.get("/auth/session", &mut browser).await.body["user"]["email"].as_str().unwrap().to_owned();
	let uri = format!("{}&csrf=attacker-chosen&email=attacker%40example.com", ask(REDIRECT));
	for _ in 0..2 {
		let shown = page(&fx, &uri, &mut browser).await;
		assert_eq!((shown.status, shown.location()), (StatusCode::OK, None), "{}", shown.html);
		assert!(shown.html.contains(&email), "{}", shown.html);
		assert!(shown.html.contains("command-line tool on this computer"), "{}", shown.html);
		assert_eq!(shown.hidden("csrf"), browser.get("ev_csrf").unwrap());
		assert!(!shown.html.contains("attacker"), "{}", shown.html);
		assert!(!shown.html.contains("<script"), "{}", shown.html);
		assert_eq!(shown.headers[header::X_FRAME_OPTIONS], "DENY");
		assert_eq!(shown.headers[header::CACHE_CONTROL], "no-store");
		assert!(shown.html.contains("<form method=\"post\" action=\"/api/auth/cli\">"), "{}", shown.html);
	}
	assert_eq!(sessions(&fx, &mut browser).await.len(), 1, "only the browser's own");
}

#[tokio::test]
async fn a_hostile_redirect_never_reaches_the_markup_unescaped() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let hostile = ask("http://127.0.0.1:1/\"><script>alert(1)</script>");
	let shown = page(&fx, &hostile, &mut browser).await;
	assert_eq!(shown.status, StatusCode::OK);
	assert!(!shown.html.contains("<script"), "{}", shown.html);
}

#[tokio::test]
async fn nobody_signed_in_is_sent_to_sign_in_and_back_here() {
	let fx = fixture!();
	let sign_in = format!("{ORIGIN}/api/auth/login?{}", query(&[("returnTo", &format!("/api/auth/cli?{}", ask(REDIRECT)))]));
	let sent = page(&fx, &ask(REDIRECT), &mut Browser::default()).await;
	assert!(sent.status.is_redirection(), "{}", sent.status);
	assert_eq!(sent.location(), Some(sign_in.as_str()));
	let pressed = press(&fx, "no-session", REDIRECT, &mut Browser::default()).await;
	assert_eq!(pressed.location(), Some(sign_in.as_str()));
	// Back from a sign-in that failed: the tool is told, whoever is signed in by then.
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	for browser in [&mut Browser::default(), &mut browser] {
		let failed = page(&fx, &format!("{}&auth_error=denied", ask(REDIRECT)), browser).await;
		assert_eq!(failed.location(), Some(format!("{REDIRECT}?error=access_denied&state={STATE}").as_str()));
	}
}

#[tokio::test]
async fn an_investor_is_refused_as_the_gate_refuses_one() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "investor").await;
	let csrf = browser.get("ev_csrf").unwrap().to_owned();
	for refused in [page(&fx, &ask(REDIRECT), &mut browser).await, press(&fx, &csrf, REDIRECT, &mut browser).await] {
		assert_eq!((refused.status, refused.location()), (StatusCode::FORBIDDEN, None));
	}
	assert!(!sessions(&fx, &mut browser).await.is_empty(), "and stays signed in elsewhere");
}

#[tokio::test]
async fn a_forged_press_mints_nothing() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let forged = press(&fx, "not-the-token", REDIRECT, &mut browser).await;
	assert_eq!((forged.status, forged.location()), (StatusCode::FORBIDDEN, None));
}

#[tokio::test]
async fn a_code_goes_only_to_a_loopback_address_literal() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let csrf = browser.get("ev_csrf").unwrap().to_owned();
	for bad in [
		"http://localhost:49152/callback",
		"https://127.0.0.1:49152/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:0/callback",
		"http://127.0.0.1:65536/callback",
		"http://127.0.0.1:+80/callback",
		"http://127.0.0.1:49152",
		"http://127.0.0.1:49152?x=/",
		"http://127.0.0.1:49152@evil.example/",
		"http://u:p@127.0.0.1:49152/",
		"http://127.0.0.1:49152/callback#fragment",
		"http://127.0.0.1:49152/a b",
		"http://127.0.0.1:49152/a\nb",
		"http://127.0.0.1:49152\\@evil.example/",
		"http://127.0.0.1.evil.example:49152/",
		"http://127.1:49152/",
		"http://127.0.0.2:49152/",
		"http://[::]:49152/",
		"http://[::ffff:127.0.0.1]:49152/",
		"HTTP://127.0.0.1:49152/",
		"//127.0.0.1:49152/",
		"tedi://callback",
		"",
	] {
		let shown = page(&fx, &ask(bad), &mut browser).await;
		assert_eq!((shown.status, shown.location()), (StatusCode::BAD_REQUEST, None), "{bad:?}");
		let pressed = press(&fx, &csrf, bad, &mut browser).await;
		assert_eq!((pressed.status, pressed.location()), (StatusCode::BAD_REQUEST, None), "{bad:?}");
	}
	for good in ["http://127.0.0.1:1/", "http://[::1]:65535/callback?x=1"] {
		assert_eq!(page(&fx, &ask(good), &mut browser).await.status, StatusCode::OK, "{good:?}");
		let pressed = press(&fx, &csrf, good, &mut browser).await;
		assert_eq!(pressed.status, StatusCode::SEE_OTHER, "{good:?}");
		assert!(pressed.location().unwrap().starts_with(good), "{good:?}");
	}
}

#[tokio::test]
async fn a_request_without_state_or_an_s256_challenge_is_refused() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let challenge = s256_challenge(VERIFIER);
	let whole = [
		("redirect_uri", REDIRECT),
		("state", STATE),
		("code_challenge", challenge.as_str()),
		("code_challenge_method", "S256"),
	];
	for (at, replacement) in [(0, None), (1, None), (1, Some("")), (2, None), (2, Some(VERIFIER.split_at(40).0)), (3, None), (3, Some("plain"))] {
		let mut pairs = whole.to_vec();
		match replacement {
			Some(value) => pairs[at].1 = value,
			None => drop(pairs.remove(at)),
		}
		let shown = page(&fx, &query(&pairs), &mut browser).await;
		assert_eq!((shown.status, shown.location()), (StatusCode::BAD_REQUEST, None), "{pairs:?}");
	}
}

#[tokio::test]
async fn a_code_is_spent_once_and_a_second_presentation_revokes_what_it_bought() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let code = code(&fx, &mut browser).await;
	let (status, body) = redeem(&fx, &code, VERIFIER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let session = body["session"].as_str().unwrap();
	assert!(passes(&fx, session).await);
	assert_eq!(redeem(&fx, &code, VERIFIER).await, invalid_grant());
	assert!(!passes(&fx, session).await, "two parties held the code");
	assert_eq!(sessions(&fx, &mut browser).await.len(), 1);
}

#[tokio::test]
async fn a_code_presented_without_its_verifier_is_burned() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let code = code(&fx, &mut browser).await;
	assert_eq!(redeem(&fx, &code, "another-verifier-of-a-perfectly-fine-length-000").await, invalid_grant());
	assert_eq!(redeem(&fx, &code, VERIFIER).await, invalid_grant());
}

#[tokio::test]
async fn whatever_is_not_a_live_code_is_one_invalid_grant() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	for code in ["", "no-dot", "unknown.code", session.as_str(), browser.get("ev_session").unwrap()] {
		assert_eq!(redeem(&fx, code, VERIFIER).await, invalid_grant(), "{code:?}");
	}
	assert!(passes(&fx, &session).await, "a wrong code for its family ends nothing");
	for body in ["", "{}", "[]", "{\"code\":\"x\"}"] {
		let request = Request::builder().method(Method::POST).uri("/auth/cli/token").header(header::CONTENT_TYPE, "application/json");
		let answer = send(&fx, request, Body::from(body), &mut Browser::default()).await;
		assert_eq!((answer.status, answer.html.as_str()), (StatusCode::BAD_REQUEST, "{\"error\":\"invalid_grant\"}"), "{body:?}");
	}
}

#[tokio::test]
async fn a_code_outlives_neither_its_minute_nor_what_it_was_issued_on() {
	let fx = fixture!();
	for lost in ["token_version = token_version + 1", "status = 'disabled'", "role = 'investor'"] {
		let (mut browser, id) = signed_in_as(&fx, "operator").await;
		let code = code(&fx, &mut browser).await;
		set(&fx, &id, lost).await;
		assert_eq!(redeem(&fx, &code, VERIFIER).await, invalid_grant(), "{lost}");
	}
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let code = code(&fx, &mut browser).await;
	let now = concierge_now();
	if !rewrite(&code, &[("expires_at", now - 1)]).await {
		return;
	}
	assert_eq!(redeem(&fx, &code, VERIFIER).await, invalid_grant());
}

fn concierge_now() -> i64 {
	i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap()
}

#[tokio::test]
async fn a_session_slides_on_use_and_lapses_unused() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	let now = concierge_now();
	if !rewrite(&session, &[("expires_at", now + 60), ("last_seen", now - 600)]).await {
		return;
	}
	assert!(passes(&fx, &session).await);
	let mut conn = redis::Client::open(std::env::var("REDIS_URL").unwrap())
		.unwrap()
		.get_multiplexed_async_connection()
		.await
		.unwrap();
	let (expires_at, last_seen): (i64, i64) = redis::cmd("HMGET")
		.arg(family_key(&session))
		.arg(&["expires_at", "last_seen"])
		.query_async(&mut conn)
		.await
		.unwrap();
	assert!((now + 3600..now + 3660).contains(&expires_at), "a whole window from the use: {}", expires_at - now);
	assert!(last_seen >= now);
	assert!(rewrite(&session, &[("absolute_expires_at", now + 90)]).await);
	assert!(passes(&fx, &session).await);
	let expires_at: i64 = redis::cmd("HGET").arg(family_key(&session)).arg("expires_at").query_async(&mut conn).await.unwrap();
	assert_eq!(expires_at, now + 90, "and never past the absolute deadline");
	assert!(rewrite(&session, &[("expires_at", now - 1)]).await);
	assert!(!passes(&fx, &session).await);
}

#[tokio::test]
async fn a_session_is_no_cookie_and_opens_nothing_but_the_gate() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	for names in [["ev_session", "ev_csrf"], ["ev_access", "ev_csrf"]] {
		let held = Browser {
			cookies: names.map(|name| (name.to_owned(), session.clone())).to_vec(),
		};
		assert_eq!(fx.get("/auth/session", &mut held.clone()).await.body["authenticated"], false, "{names:?}");
		assert_eq!(fx.get("/auth/sessions", &mut held.clone()).await.status, StatusCode::UNAUTHORIZED, "{names:?}");
		let request = Request::builder().uri("/auth/gate").header("x-forwarded-method", "GET").header("x-forwarded-uri", "/team/tasks");
		let sent = send(&fx, request, Body::empty(), &mut held.clone()).await;
		assert!(sent.location().is_some_and(|to| to.contains("/api/auth/login")), "{names:?}: {}", sent.status);
	}
	for path in ["/auth/me", "/auth/sessions", "/auth/methods"] {
		let request = Request::builder().uri(path).header(header::AUTHORIZATION, format!("Bearer {session}"));
		assert_eq!(send(&fx, request, Body::empty(), &mut Browser::default()).await.status, StatusCode::UNAUTHORIZED, "{path}");
	}
	assert!(passes(&fx, &session).await);
}

#[tokio::test]
async fn a_bad_bearer_is_refused_and_never_redirected() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	let (family, _) = session.split_once('.').unwrap();
	let pending = code(&fx, &mut browser).await;
	let wrong_secret = format!("Bearer {family}.wrong");
	let unredeemed = format!("Bearer {pending}");
	let basic = format!("Basic {session}");
	for authorization in ["", "Bearer", "Bearer ", "Bearer no-dot", "Bearer unknown.secret", &wrong_secret, &unredeemed, &basic] {
		assert_refused(&gate(&fx, authorization, &mut Browser::default()).await);
		let cookies = browser.cookies.clone();
		assert_refused(&gate(&fx, authorization, &mut browser).await);
		assert_eq!(browser.cookies, cookies, "{authorization:?}: the browser's own session is neither read nor ended");
	}
	assert!(passes(&fx, &session).await, "a guess ends nothing");
	let scheme = gate(&fx, &format!("bearer {session}"), &mut Browser::default()).await;
	assert_eq!(scheme.status, StatusCode::NO_CONTENT, "a scheme has no case");
}

#[tokio::test]
async fn the_browsers_sign_out_leaves_the_tool_signed_in() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	let out = fx.post("/auth/logout", ORIGIN, json!({}), &mut browser).await;
	assert_eq!(out.status, StatusCode::OK);
	assert!(passes(&fx, &session).await);
}

#[tokio::test]
async fn a_tool_is_listed_as_one_and_revoked_like_any_session() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	let _unredeemed = code(&fx, &mut browser).await;
	let listed = sessions(&fx, &mut browser).await;
	let (tools, browsers): (Vec<_>, Vec<_>) = listed.iter().partition(|s| s["cli"] == true);
	let ([tool], [own]) = (tools.as_slice(), browsers.as_slice()) else {
		panic!("one tool and one browser, no code: {listed:?}");
	};
	assert_eq!((&tool["user_agent"], &tool["current"]), (&json!("tedi/1.0"), &json!(false)));
	assert_eq!(own["current"], true);
	let revoked = fx
		.send(Method::DELETE, "/auth/sessions", ORIGIN, Some(json!({ "session_id": tool["id"] })), &mut browser, true)
		.await;
	assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
	assert!(!passes(&fx, &session).await);
	assert_eq!(sessions(&fx, &mut browser).await.len(), 1, "the browser's own stays");
}

#[tokio::test]
async fn a_session_dies_with_the_seat_the_account_or_the_token_version() {
	let fx = fixture!();
	for (lost, regained) in [
		("role = 'investor'", "role = 'operator'"),
		("status = 'disabled'", "status = 'active'"),
		("token_version = token_version + 1", "token_version = token_version - 1"),
	] {
		let (mut browser, id) = signed_in_as(&fx, "operator").await;
		let session = signed_in_tool(&fx, &mut browser).await;
		set(&fx, &id, lost).await;
		assert!(!passes(&fx, &session).await, "{lost}");
		set(&fx, &id, regained).await;
		assert!(!passes(&fx, &session).await, "{lost}: ended, not suspended");
	}
}

#[tokio::test]
async fn another_seat_keeps_the_session() {
	let fx = fixture!();
	let (mut browser, id) = signed_in_as(&fx, "operator").await;
	let session = signed_in_tool(&fx, &mut browser).await;
	set(&fx, &id, "role = 'admin'").await;
	assert!(passes(&fx, &session).await);
}
