//! `GET /auth/gate`: Traefik's ForwardAuth asks it about every request to a staff-only
//! page on the apex, and relays its answer — a pass naming the account, a sign-in, or a
//! refusal.

use crate::common;

use axum::{
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::web::{Browser, ORIGIN, Surface, address, surface};
use tower::ServiceExt;

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

const PAGE: &str = "/team/tasks?view=mine";

/// The request Traefik makes for `method uri` on the apex: the browser's cookies, the
/// original request in `X-Forwarded-*`.
async fn ask(fx: &Surface, method: &str, uri: &str, browser: &mut Browser) -> (StatusCode, HeaderMap) {
	let mut request = Request::builder()
		.method(Method::GET)
		.uri("/auth/gate")
		.header("x-forwarded-method", method)
		.header("x-forwarded-proto", "https")
		.header("x-forwarded-host", "evinvest.ltd")
		.header("x-forwarded-uri", uri);
	if !browser.cookies.is_empty() {
		request = request.header(header::COOKIE, browser.header());
	}
	let response = fx.router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
	browser.absorb(response.headers());
	(response.status(), response.headers().clone())
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

fn sign_in_for(page: &str) -> String {
	let query = form_urlencoded::Serializer::new(String::new()).append_pair("returnTo", page).finish();
	format!("{ORIGIN}/api/auth/login?{query}")
}

fn clears_the_session(headers: &HeaderMap) -> bool {
	headers.get_all(header::SET_COOKIE).iter().any(|c| c.to_str().unwrap().starts_with("ev_session=;"))
}

#[tokio::test]
async fn staff_pass_named_by_their_account_id() {
	let fx = fixture!();
	for role in ["operator", "admin", "owner"] {
		let (mut browser, id) = signed_in_as(&fx, role).await;
		let (status, headers) = ask(&fx, "GET", PAGE, &mut browser).await;
		assert!(status.is_success(), "{role}: {status}");
		assert_eq!(headers["x-auth-user"], id.as_str(), "{role}");
	}
}

#[tokio::test]
async fn an_investor_is_refused_without_a_name() {
	let fx = fixture!();
	let (mut browser, _) = signed_in_as(&fx, "investor").await;
	let (status, headers) = ask(&fx, "GET", PAGE, &mut browser).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	assert!(!headers.contains_key("x-auth-user"));
	assert!(!clears_the_session(&headers), "the investor stays signed in elsewhere");
}

#[tokio::test]
async fn nobody_signed_in_is_sent_to_sign_in_and_back_to_the_page() {
	let fx = fixture!();
	let mut anonymous = Browser::default();
	for (asked, back) in [(PAGE, PAGE), ("//evil.example/x", "/"), ("/\\evil.example", "/"), ("https://evil.example/", "/")] {
		let (status, headers) = ask(&fx, "GET", asked, &mut anonymous).await;
		assert!(status.is_redirection(), "{asked}: {status}");
		assert_eq!(headers[header::LOCATION], sign_in_for(back).as_str(), "{asked}");
		assert!(!headers.contains_key("x-auth-user"));
	}
	// Not a navigation, or back from a sign-in that failed: answered, never sent round again.
	assert_eq!(ask(&fx, "POST", PAGE, &mut anonymous).await.0, StatusCode::UNAUTHORIZED);
	assert_eq!(ask(&fx, "GET", "/team/tasks?auth_error=denied", &mut anonymous).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_ended_session_is_closed_and_sent_to_sign_in() {
	let fx = fixture!();
	let (mut browser, id) = signed_in_as(&fx, "operator").await;
	let kept = browser.clone();
	sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1::uuid")
		.bind(&id)
		.execute(&fx.db.pool)
		.await
		.unwrap();
	let (status, headers) = ask(&fx, "GET", PAGE, &mut browser).await;
	assert!(status.is_redirection(), "{status}");
	assert_eq!(headers[header::LOCATION], sign_in_for(PAGE).as_str());
	assert!(clears_the_session(&headers));
	assert!(!headers.contains_key("x-auth-user"));
	assert!(
		!ask(&fx, "GET", PAGE, &mut kept.clone()).await.0.is_success(),
		"closed server-side, not only forgotten by this browser"
	);
}
