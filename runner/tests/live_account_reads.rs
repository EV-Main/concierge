//! The read routes answer a live account only (#132). A blocked account's session, or a
//! squatter's session on an account its mailbox's owner took over, is refused on every
//! read exactly as on `/auth/me`: refused, its cookies cleared and the session closed
//! server-side. `/auth/session` is the one read that does not refuse — it is who-am-I for
//! every zone, so it answers `authenticated: false` and ends the session the same way.

mod common;

use axum::http::{StatusCode, header};
use common::web::{Browser, ORIGIN, Surface, address, surface};
use serde_json::{Value, json};

macro_rules! fixture {
	() => {
		match surface().await.filter(|_| redis_shared()) {
			Some(fx) => fx,
			None => return,
		}
	};
}

/// The reads a signed-in browser makes besides `/auth/me`, which `account_routes` covers.
const READS: [&str; 3] = ["/auth/sessions", "/auth/methods", "/kyc/status"];

async fn signed_in(fx: &Surface, email: &str) -> Browser {
	let mut browser = Browser::default();
	let done = fx.sign_in_with_code(email, &mut browser).await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	browser
}

fn clears_the_session(headers: &axum::http::HeaderMap) -> bool {
	headers.get_all(header::SET_COOKIE).iter().any(|c| c.to_str().unwrap().starts_with("ev_session=;"))
}

async fn user_id(fx: &Surface, browser: &mut Browser) -> uuid::Uuid {
	uuid::Uuid::parse_str(fx.get("/auth/me", browser).await.body["id"].as_str().unwrap()).unwrap()
}

/// Whether the session locker still holds the session the cookies taken before the
/// refusal name. Asked of the store and not of a route: every read now ends such a
/// session itself, so asking one would close what it was meant to observe.
async fn still_open(kept: &Browser) -> bool {
	let id = kept.get("ev_session").expect("the browser held a session");
	let sessions = concierge::web::WebSessions::from_env().await.expect("session store");
	sessions.csrf(id).await.expect("session store read").is_some()
}

/// The locker is shared with the router only through Redis: an in-process store here
/// would be a second, empty one and report every session closed.
fn redis_shared() -> bool {
	let shared = std::env::var("REDIS_URL").is_ok_and(|url| !url.is_empty());
	if !shared {
		eprintln!("SKIPPED: REDIS_URL unset — the session locker cannot be inspected from here");
	}
	shared
}

/// Every read refuses the session with `refusal`, ends it, and `/auth/session` then says
/// nobody is signed in. Each read spends a session of its own: the first refusal ends it.
async fn every_read_ends_the_session(fx: &Surface, mut sessions: Vec<Browser>, refusal: (StatusCode, Value)) {
	for path in READS {
		let mut browser = sessions.pop().expect("a session per read");
		let kept = browser.clone();
		let refused = fx.get(path, &mut browser).await;
		assert_eq!((refused.status, refused.body), refusal.clone(), "{path}");
		assert!(clears_the_session(&refused.headers), "{path}: the cookies are cleared");
		assert!(!still_open(&kept).await, "{path}: the session is closed, not only forgotten by this browser");
	}

	let mut browser = sessions.pop().expect("a session per read");
	let kept = browser.clone();
	let answer = fx.get("/auth/session", &mut browser).await;
	assert_eq!(answer.status, StatusCode::OK);
	assert_eq!(answer.body["authenticated"], false, "{:?}", answer.body);
	assert!(answer.body.get("user").is_none(), "{:?}", answer.body);
	assert!(clears_the_session(&answer.headers), "/auth/session: the cookies are cleared");
	assert!(!still_open(&kept).await, "/auth/session: the session is closed");
}

#[tokio::test]
async fn a_live_account_reads_as_before() {
	let fx = fixture!();
	let mut browser = signed_in(&fx, &address("live")).await;
	for path in READS {
		let answer = fx.get(path, &mut browser).await;
		assert_eq!(answer.status, StatusCode::OK, "{path}: {:?}", answer.body);
	}
	let session = fx.get("/auth/session", &mut browser).await;
	assert_eq!(session.body["authenticated"], true);
}

#[tokio::test]
async fn a_disabled_account_reads_nothing_and_its_session_ends() {
	let fx = fixture!();
	let email = address("blocked");
	let mut first = signed_in(&fx, &email).await;
	let id = user_id(&fx, &mut first).await;
	// Sessions are opened before the block: a disabled account cannot sign in again.
	let mut sessions = Vec::new();
	for _ in 0..=READS.len() {
		sessions.push(signed_in(&fx, &email).await);
	}
	sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(id).execute(&fx.pool).await.unwrap();

	every_read_ends_the_session(&fx, sessions, (StatusCode::FORBIDDEN, json!({ "error": "disabled" }))).await;
}

/// The squatter registered the address unverified with a password; its owner then proved
/// the mailbox with a code, which takes the account over and bumps its `token_version`.
#[tokio::test]
async fn a_taken_over_account_reads_nothing_and_the_squatters_session_ends() {
	let fx = fixture!();
	let email = address("squatted");
	let mut squatter = Vec::new();
	for _ in 0..=READS.len() {
		let mut browser = Browser::default();
		let opened = fx
			.post(
				"/auth/password/signup",
				ORIGIN,
				json!({ "email": email, "password": "correct horse battery", "verify": false, "turnstileToken": "human" }),
				&mut browser,
			)
			.await;
		if squatter.is_empty() {
			assert_eq!(opened.status, StatusCode::OK, "{:?}", opened.body);
		} else {
			let again = fx
				.post(
					"/auth/password/signin",
					ORIGIN,
					json!({ "identifier": email, "password": "correct horse battery", "turnstileToken": "human" }),
					&mut browser,
				)
				.await;
			assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
		}
		squatter.push(browser);
	}
	signed_in(&fx, &email).await;

	every_read_ends_the_session(&fx, squatter, (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" }))).await;
}
