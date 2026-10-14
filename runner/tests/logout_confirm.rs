//! `/auth/logout/confirm`: the page a scope's host sends the browser to so that signing
//! out there ends the `evinvest.ltd` session too.

mod common;

use axum::{
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::web::{Browser, INVEST, ORIGIN, Surface, address, surface};
use tower::ServiceExt;

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

/// Seeded by migration 0031: `invest` lands sign-ins on `/cabinet`.
fn invest_landing() -> String {
	format!("{INVEST}/cabinet")
}

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
}

async fn send(fx: &Surface, request: axum::http::request::Builder, body: Body, browser: &mut Browser) -> Page {
	let mut request = request;
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
	let mut q = form_urlencoded::Serializer::new(String::new());
	for (k, v) in pairs {
		q.append_pair(k, v);
	}
	q.finish()
}

async fn page(fx: &Surface, return_to: &str, browser: &mut Browser) -> Page {
	let uri = format!("/auth/logout/confirm?{}", query(&[("return_to", return_to)]));
	send(fx, Request::builder().method(Method::GET).uri(uri), Body::empty(), browser).await
}

async fn press(fx: &Surface, csrf: &str, return_to: &str, browser: &mut Browser) -> Page {
	let request = Request::builder()
		.method(Method::POST)
		.uri("/auth/logout/confirm")
		.header(header::ORIGIN, ORIGIN)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
	send(fx, request, Body::from(query(&[("csrf", csrf), ("return_to", return_to)])), browser).await
}

async fn signed_in(fx: &Surface) -> Browser {
	let mut browser = Browser::default();
	let answer = fx.sign_in_with_code(&address("logout"), &mut browser).await;
	assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
	browser
}

async fn authenticated(fx: &Surface, browser: &mut Browser) -> bool {
	fx.get("/auth/session", browser).await.body["authenticated"] == true
}

#[tokio::test]
async fn without_a_session_the_page_sends_the_browser_straight_back() {
	let fx = fixture!();
	let back = page(&fx, &invest_landing(), &mut Browser::default()).await;
	assert_eq!((back.status, back.location()), (StatusCode::SEE_OTHER, Some(invest_landing().as_str())));
}

/// The account chip and `@evinvest/concierge` sign out to the host's root, so a scope
/// that mounts them must list `/` (migration 0035 for `invest`); without it the page
/// answered 400 and the platform session outlived the host's.
#[tokio::test]
async fn the_invest_hosts_root_is_a_landing() {
	let fx = fixture!();
	let root = format!("{INVEST}/");
	let mut browser = signed_in(&fx).await;
	let held = browser.clone();
	let shown = page(&fx, &root, &mut browser).await;
	assert_eq!((shown.status, shown.location()), (StatusCode::OK, None), "{}", shown.html);
	assert_eq!(shown.hidden("return_to"), root);
	let pressed = press(&fx, &shown.hidden("csrf"), &root, &mut browser).await;
	assert_eq!((pressed.status, pressed.location()), (StatusCode::SEE_OTHER, Some(root.as_str())));
	assert!(!authenticated(&fx, &mut held.clone()).await, "signing out at the root ends the session server-side");
	let back = page(&fx, &root, &mut Browser::default()).await;
	assert_eq!((back.status, back.location()), (StatusCode::SEE_OTHER, Some(root.as_str())));
}

#[tokio::test]
async fn a_landing_nobody_registered_gets_a_page_never_a_redirect() {
	let fx = fixture!();
	let mut browser = signed_in(&fx).await;
	for target in [
		"https://evil.example/",
		"https://invest.evinvest.ltd/elsewhere",
		"https://invest.evinvest.ltd.evil.example/cabinet",
		"/cabinet",
		"javascript:alert(1)",
		"",
	] {
		let answer = page(&fx, target, &mut browser).await;
		assert_eq!((answer.status, answer.location()), (StatusCode::BAD_REQUEST, None), "{target:?}");
		let csrf = browser.get("ev_csrf").unwrap().to_owned();
		let pressed = press(&fx, &csrf, target, &mut browser).await;
		assert_eq!((pressed.status, pressed.location()), (StatusCode::BAD_REQUEST, None), "{target:?}");
	}
	assert!(authenticated(&fx, &mut browser).await, "a refused link signs nobody out");
	let home = page(&fx, &format!("{ORIGIN}/\t/evil.example"), &mut Browser::default()).await;
	assert_eq!(home.location(), Some(format!("{ORIGIN}/").as_str()), "a path on this origin is held to the returnTo rules");
}

#[tokio::test]
async fn the_page_carries_the_sessions_token_and_never_one_from_the_link() {
	let fx = fixture!();
	let mut browser = signed_in(&fx).await;
	let uri = format!("/auth/logout/confirm?{}", query(&[("return_to", &invest_landing()), ("csrf", "attacker-chosen")]));
	let shown = send(&fx, Request::builder().method(Method::GET).uri(uri), Body::empty(), &mut browser).await;
	assert_eq!(shown.status, StatusCode::OK);
	assert_eq!(shown.hidden("csrf"), browser.get("ev_csrf").unwrap());
	assert_eq!(shown.hidden("return_to"), invest_landing());
	assert!(!shown.html.contains("attacker-chosen"));
	let csp = shown.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
	assert!(csp.starts_with("default-src 'none'; form-action 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
	assert_eq!(shown.headers[header::X_FRAME_OPTIONS], "DENY");
	assert_eq!(shown.headers[header::CACHE_CONTROL], "no-store");
	assert!(!shown.html.contains("<script") && !shown.html.contains("src="), "the page loads nothing");
	assert!(authenticated(&fx, &mut browser).await, "showing the page signs nobody out");
}

#[tokio::test]
async fn pressing_the_button_ends_the_session_and_goes_back() {
	let fx = fixture!();
	let mut browser = signed_in(&fx).await;
	let held = browser.clone();
	let shown = page(&fx, &invest_landing(), &mut browser).await;
	let pressed = press(&fx, &shown.hidden("csrf"), &shown.hidden("return_to"), &mut browser).await;
	assert_eq!((pressed.status, pressed.location()), (StatusCode::SEE_OTHER, Some(invest_landing().as_str())));
	assert!(browser.get("ev_session").is_none(), "the cookies are cleared");
	assert!(!authenticated(&fx, &mut held.clone()).await, "and the session is over server-side");
}

#[tokio::test]
async fn a_forged_press_signs_nobody_out() {
	let fx = fixture!();
	let mut browser = signed_in(&fx).await;
	let forged = press(&fx, "not-the-token", &invest_landing(), &mut browser).await;
	assert_eq!((forged.status, forged.location()), (StatusCode::FORBIDDEN, None));
	assert!(authenticated(&fx, &mut browser).await);
}
