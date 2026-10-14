//! Confirming a password sign-up with its ticket (`POST /auth/password/signup/confirm`):
//! the address is verified on the account just made and its password stays — unlike a
//! code SIGN-IN on that mailbox, which still takes an unverified password account over.

mod common;

use axum::http::{StatusCode, header};
use common::web::{Answer, Browser, INVEST, ORIGIN, Surface, address, surface};
use serde_json::{Value, json};

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

const PASSWORD: &str = "correct horse battery";

async fn sign_up(fx: &Surface, origin: &str, email: &str, browser: &mut Browser) -> Answer {
	fx.post(
		"/auth/password/signup",
		origin,
		json!({ "email": email, "password": PASSWORD, "verify": true, "turnstileToken": "human" }),
		browser,
	)
	.await
}

async fn confirm(fx: &Surface, origin: &str, ticket: &Value, code: &str, browser: &mut Browser) -> Answer {
	fx.post("/auth/password/signup/confirm", origin, json!({ "ticket": ticket, "code": code }), browser).await
}

async fn resend(fx: &Surface, origin: &str, ticket: &Value, turnstile: &str) -> Answer {
	fx.post(
		"/auth/password/signup/resend",
		origin,
		json!({ "ticket": ticket, "turnstileToken": turnstile }),
		&mut Browser::default(),
	)
	.await
}

async fn queued(fx: &Surface, email: &str) -> i64 {
	sqlx::query_scalar("SELECT count(*) FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1")
		.bind(email)
		.fetch_one(&fx.pool)
		.await
		.unwrap()
}

async fn state_of(fx: &Surface, email: &str) -> (bool, bool) {
	sqlx::query_as("SELECT u.email_verified, EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = u.id) FROM users u WHERE u.email = $1")
		.bind(email)
		.fetch_one(&fx.pool)
		.await
		.unwrap()
}

#[tokio::test]
async fn a_sign_up_on_a_scope_host_confirms_its_address_and_keeps_its_password() {
	let fx = fixture!();
	let email = address("ticket");
	let mut browser = Browser::default();
	let made = sign_up(&fx, INVEST, &email, &mut browser).await;
	assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
	assert_eq!(made.body["verification"], "sent");
	assert_eq!(made.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	let ticket = made.body["ticket"].clone();
	assert!(ticket.as_str().is_some_and(|t| t.len() >= 43), "256 bits: {ticket}");

	let code = fx.mailed_code(&email, "verify").await;
	let done = confirm(&fx, INVEST, &ticket, &code, &mut browser).await;
	assert_eq!((done.status, done.body), (StatusCode::OK, json!({ "ok": true })));
	assert_eq!(done.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	assert!(browser.get("ev_session").is_some());
	assert_eq!(state_of(&fx, &email).await, (true, true), "verified, and the password is still there");

	let again = confirm(&fx, INVEST, &ticket, &code, &mut Browser::default()).await;
	assert_eq!(
		(again.status, again.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })),
		"a ticket is spent once"
	);
}

/// A wrong code, an unknown ticket and someone else's ticket all answer alike, so the
/// ticket cannot be probed apart from the code.
#[tokio::test]
async fn a_wrong_ticket_or_code_answers_one_way() {
	let fx = fixture!();
	let (mine, theirs) = (address("mine"), address("theirs"));
	let my_ticket = sign_up(&fx, INVEST, &mine, &mut Browser::default()).await.body["ticket"].clone();
	let their_ticket = sign_up(&fx, INVEST, &theirs, &mut Browser::default()).await.body["ticket"].clone();
	let my_code = fx.mailed_code(&mine, "verify").await;
	let wrong = format!("{:06}", (my_code.parse::<u32>().unwrap() + 1) % 1_000_000);

	let refused = json!({ "error": "invalid_code" });
	for (ticket, code) in [(&my_ticket, wrong.as_str()), (&json!("not-a-ticket"), my_code.as_str()), (&their_ticket, my_code.as_str())] {
		let answer = confirm(&fx, INVEST, ticket, code, &mut Browser::default()).await;
		assert_eq!((answer.status, answer.body), (StatusCode::BAD_REQUEST, refused.clone()), "{ticket} / {code}");
	}
	assert_eq!(state_of(&fx, &mine).await, (false, true));
	assert_eq!(state_of(&fx, &theirs).await, (false, true));

	let done = confirm(&fx, INVEST, &my_ticket, &my_code, &mut Browser::default()).await;
	assert_eq!(done.status, StatusCode::OK, "a wrong guess leaves the ticket: {:?}", done.body);
}

/// The takeover rule stands for every other path: a code sign-in on an unverified
/// password account still drops the password — and kills a ticket issued before it.
#[tokio::test]
async fn a_code_sign_in_without_the_ticket_still_takes_the_account_over() {
	let fx = fixture!();
	let email = address("squat");
	let ticket = sign_up(&fx, INVEST, &email, &mut Browser::default()).await.body["ticket"].clone();
	let verify_code = fx.mailed_code(&email, "verify").await;

	let taken = fx.sign_in_with_code(&email, &mut Browser::default()).await;
	assert_eq!(taken.status, StatusCode::OK, "{:?}", taken.body);
	assert_eq!(state_of(&fx, &email).await, (true, false), "the mailbox owns the account; the password is gone");

	let late = confirm(&fx, INVEST, &ticket, &verify_code, &mut Browser::default()).await;
	assert_eq!(
		(late.status, late.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })),
		"the takeover outlived the ticket"
	);
}

#[tokio::test]
async fn the_confirmation_is_a_sign_in_step_with_its_guards() {
	let fx = fixture!();
	let email = address("guards");
	let ticket = sign_up(&fx, ORIGIN, &email, &mut Browser::default()).await.body["ticket"].clone();
	let code = fx.mailed_code(&email, "verify").await;

	let foreign = confirm(&fx, "https://evil.example", &ticket, &code, &mut Browser::default()).await;
	assert_eq!((foreign.status, foreign.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
	let foreign = resend(&fx, "https://evil.example", &ticket, "human").await;
	assert_eq!((foreign.status, foreign.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
	let bot = resend(&fx, ORIGIN, &ticket, "robot").await;
	assert_eq!((bot.status, bot.body), (StatusCode::FORBIDDEN, json!({ "error": "captcha" })), "a resend costs a mail");
	let code = fx.mailed_code(&email, "verify").await;

	let done = confirm(&fx, ORIGIN, &ticket, &code, &mut Browser::default()).await;
	assert_eq!(done.status, StatusCode::OK, "this plane's own origin confirms too: {:?}", done.body);
}

#[tokio::test]
async fn a_sign_up_that_mails_no_code_hands_out_no_ticket() {
	let fx = fixture!();
	let made = fx
		.post(
			"/auth/password/signup",
			ORIGIN,
			json!({ "email": address("later"), "password": PASSWORD, "verify": false, "turnstileToken": "human" }),
			&mut Browser::default(),
		)
		.await;
	assert_eq!(made.body["verification"], "skipped");
	assert_eq!(made.body["ticket"], Value::Null);
	assert!(made.body.get("ticket_error").is_none(), "no ticket is owed when no code went out");
}

/// The ticket outlives its code: a code that expired is recovered by a resend under the
/// same ticket, and the new code — not the old — confirms.
#[tokio::test]
async fn an_expired_code_is_recovered_by_a_resend_under_the_same_ticket() {
	let fx = fixture!();
	let email = address("resend");
	let ticket = sign_up(&fx, INVEST, &email, &mut Browser::default()).await.body["ticket"].clone();
	let first = fx.mailed_code(&email, "verify").await;
	sqlx::query("UPDATE email_codes SET expires_at = 0 WHERE email = $1 AND purpose = 'verify'")
		.bind(&email)
		.execute(&fx.pool)
		.await
		.unwrap();
	let late = confirm(&fx, INVEST, &ticket, &first, &mut Browser::default()).await;
	assert_eq!((late.status, late.body), (StatusCode::BAD_REQUEST, json!({ "error": "code_expired" })));

	let again = resend(&fx, INVEST, &ticket, "human").await;
	assert_eq!((again.status, again.body.clone()), (StatusCode::OK, json!({ "ok": true })));
	assert_eq!(again.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	let second = fx.mailed_code(&email, "verify").await;
	assert_ne!(first, second);

	let done = confirm(&fx, INVEST, &ticket, &second, &mut Browser::default()).await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	assert_eq!(state_of(&fx, &email).await, (true, true));

	// A dead ticket answers exactly as a live one and mails nothing: the ticket cannot be
	// probed here apart from the code.
	let before = queued(&fx, &email).await;
	let spent = resend(&fx, INVEST, &ticket, "human").await;
	assert_eq!((spent.status, spent.body), (StatusCode::OK, json!({ "ok": true })));
	let unknown = resend(&fx, INVEST, &json!("not-a-ticket"), "human").await;
	assert_eq!((unknown.status, unknown.body), (StatusCode::OK, json!({ "ok": true })));
	assert_eq!(queued(&fx, &email).await, before, "no mail went out for a dead ticket");
}

#[tokio::test]
async fn a_resend_is_throttled_like_every_code() {
	let fx = fixture!();
	let email = address("throttle");
	let ticket = sign_up(&fx, INVEST, &email, &mut Browser::default()).await.body["ticket"].clone();
	// The sign-up's own code is the first of the window.
	for _ in 1..concierge::ports::CODE_SENDS_PER_WINDOW {
		assert_eq!(resend(&fx, INVEST, &ticket, "human").await.status, StatusCode::OK);
	}
	let throttled = resend(&fx, INVEST, &ticket, "human").await;
	assert_eq!((throttled.status, throttled.body), (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "throttled" })));
}

/// A code was asked for but not sent — throttled here — and the ticket still comes back:
/// `resend` is how that sign-up confirms once the window passes.
#[tokio::test]
async fn a_sign_up_whose_code_was_throttled_still_gets_its_ticket() {
	let fx = fixture!();
	let email = address("crowded");
	for _ in 0..concierge::ports::CODE_SENDS_PER_WINDOW {
		let asked = fx
			.post("/auth/code/request", ORIGIN, json!({ "email": email, "turnstileToken": "human" }), &mut Browser::default())
			.await;
		assert_eq!(asked.status, StatusCode::OK);
	}
	let made = sign_up(&fx, INVEST, &email, &mut Browser::default()).await;
	assert_eq!(made.body["verification"], "throttled");
	assert!(made.body["ticket"].is_string(), "{:?}", made.body);
	assert!(made.body.get("ticket_error").is_none());
}

/// A disabled account is refused before anything is written: the address stays
/// unverified, the code unspent and the ticket alive.
#[tokio::test]
async fn a_disabled_account_confirms_nothing() {
	let fx = fixture!();
	let email = address("disabled");
	let ticket = sign_up(&fx, INVEST, &email, &mut Browser::default()).await.body["ticket"].clone();
	let code = fx.mailed_code(&email, "verify").await;
	let status = |s: &'static str| sqlx::query("UPDATE users SET status = $2 WHERE email = $1").bind(email.clone()).bind(s);

	status("disabled").execute(&fx.pool).await.unwrap();
	let refused = confirm(&fx, INVEST, &ticket, &code, &mut Browser::default()).await;
	assert_eq!((refused.status, refused.body), (StatusCode::FORBIDDEN, json!({ "error": "disabled" })));
	assert_eq!(state_of(&fx, &email).await, (false, true));
	let before = queued(&fx, &email).await;
	let resent = resend(&fx, INVEST, &ticket, "human").await;
	assert_eq!((resent.status, resent.body), (StatusCode::OK, json!({ "ok": true })));
	assert_eq!(queued(&fx, &email).await, before, "a disabled account is mailed nothing");

	status("active").execute(&fx.pool).await.unwrap();
	let done = confirm(&fx, INVEST, &ticket, &code, &mut Browser::default()).await;
	assert_eq!(done.status, StatusCode::OK, "the same code and ticket still work: {:?}", done.body);
}
