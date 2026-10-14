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
	fx.post(
		"/auth/password/signup/confirm",
		origin,
		json!({ "ticket": ticket, "code": code, "turnstileToken": "human" }),
		browser,
	)
	.await
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
	let bot = fx
		.post(
			"/auth/password/signup/confirm",
			ORIGIN,
			json!({ "ticket": ticket, "code": code, "turnstileToken": "robot" }),
			&mut Browser::default(),
		)
		.await;
	assert_eq!((bot.status, bot.body), (StatusCode::FORBIDDEN, json!({ "error": "captcha" })));

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
	assert!(made.body.get("ticket").is_none());
}
