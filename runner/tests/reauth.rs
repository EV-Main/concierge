//! Re-authentication (#166): the signed-in account proves itself again and the session's
//! `auth_time` moves without a new session — through the router a browser reaches.

mod common;

use axum::http::{Method, StatusCode};
use common::web::{Answer, Browser, ORIGIN, Surface, address, surface};
use serde_json::{Value, json};

macro_rules! fixture {
	() => {
		match surface().await {
			Some(fx) => fx,
			None => return,
		}
	};
}

/// The claims of the access token in the browser's cookie jar, unverified: the jar holds
/// what this plane just minted.
fn access_claims(browser: &Browser) -> Value {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	let token = browser.get("ev_access").expect("an access cookie");
	serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

impl Surface {
	async fn reauth_code(&self, browser: &mut Browser) -> Answer {
		self.post("/auth/reauth/code/request", ORIGIN, json!({ "turnstileToken": "human" }), browser).await
	}

	/// The newest re-authentication code queued for the address.
	async fn own_code(&self, email: &str) -> String {
		self.mailed_code(email, "reauth").await
	}
}

#[tokio::test]
async fn a_mailed_code_moves_auth_time_and_re_sets_the_access_cookie() {
	let fx = fixture!();
	let email = address("reauth-code");
	let mut browser = Browser::default();
	assert_eq!(fx.sign_in_with_code(&email, &mut browser).await.status, StatusCode::OK);
	let before = access_claims(&browser);
	let session_cookie = browser.get("ev_session").unwrap().to_owned();

	assert_eq!(fx.reauth_code(&mut browser).await.body, json!({ "ok": true }));
	let code = fx.own_code(&email).await;

	let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
	let refused = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": wrong }), &mut browser).await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })));
	assert_eq!(access_claims(&browser)["jti"], before["jti"], "a refusal leaves the token alone");

	let done = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": code }), &mut browser).await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	let after = access_claims(&browser);
	assert_ne!(after["jti"], before["jti"], "a new access token was minted");
	assert_eq!(done.body["authTime"], after["auth_time"], "the answer and the token agree");
	assert!(after["auth_time"].as_u64() >= before["auth_time"].as_u64());
	assert_eq!(after["sub"], before["sub"]);
	assert_eq!(browser.get("ev_session"), Some(session_cookie.as_str()), "no new session");

	let session = fx.get("/auth/session", &mut browser).await;
	assert_eq!(session.body["authenticated"], true);
	assert_eq!(access_claims(&browser)["auth_time"], after["auth_time"], "a later refresh keeps the moved time");
}

#[tokio::test]
async fn a_code_works_once_and_only_for_its_own_purpose() {
	let fx = fixture!();
	let email = address("reauth-purpose");
	let mut browser = Browser::default();
	fx.sign_in_with_code(&email, &mut browser).await;
	let login_code = fx.mailed_code(&email, "login").await;
	fx.reauth_code(&mut browser).await;
	let code = fx.own_code(&email).await;

	let wrong_kind = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": login_code }), &mut browser).await;
	assert_eq!(
		(wrong_kind.status, wrong_kind.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })),
		"a sign-in code is not a re-auth code"
	);
	let mut stranger = Browser::default();
	let as_login = fx.post("/auth/code/verify", ORIGIN, json!({ "email": email, "code": code }), &mut stranger).await;
	assert_eq!(as_login.status, StatusCode::BAD_REQUEST, "a re-auth code signs nobody in");

	let first = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": code }), &mut browser).await;
	assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
	let again = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": code }), &mut browser).await;
	assert_eq!((again.status, again.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })), "a code is spent once");
}

#[tokio::test]
async fn the_code_mail_says_what_it_is_for() {
	let fx = fixture!();
	let email = address("reauth-mail");
	let mut browser = Browser::default();
	fx.sign_in_with_code(&email, &mut browser).await;
	fx.reauth_code(&mut browser).await;
	let purpose: String = sqlx::query_scalar("SELECT payload->>'purpose' FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1 ORDER BY id DESC LIMIT 1")
		.bind(&email)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(purpose, "reauth");
	let rendered = concierge::infrastructure::email::templates::reauth_code("123456", 0);
	assert!(rendered.text.contains("123456") && rendered.text.contains("If this was not you"));
}

#[tokio::test]
async fn a_revoked_session_cannot_re_authenticate() {
	let fx = fixture!();
	let email = address("reauth-revoked");
	let mut browser = Browser::default();
	fx.sign_in_with_code(&email, &mut browser).await;
	sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE email = $1")
		.bind(&email)
		.execute(&fx.pool)
		.await
		.unwrap();

	let refused = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
	assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));
	assert!(browser.get("ev_session").is_none(), "the dead session is cleared");
}

#[tokio::test]
async fn a_foreign_origin_is_refused_outright() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("reauth-origin"), &mut browser).await;
	let refused = fx.post("/auth/reauth/password", "https://evil.example", json!({ "password": "x" }), &mut browser).await;
	assert_eq!((refused.status, refused.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
}

#[tokio::test]
async fn a_code_mailed_to_someone_else_proves_nothing() {
	let fx = fixture!();
	let (mine, theirs) = (address("reauth-me"), address("reauth-them"));
	let mut me = Browser::default();
	fx.sign_in_with_code(&mine, &mut me).await;
	let mut them = Browser::default();
	fx.sign_in_with_code(&theirs, &mut them).await;
	fx.reauth_code(&mut them).await;
	let their_code = fx.own_code(&theirs).await;

	let before = access_claims(&me);
	let refused = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": their_code }), &mut me).await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })));
	assert_eq!(access_claims(&me)["jti"], before["jti"]);
}

#[tokio::test]
async fn a_password_re_authenticates_only_its_own_account() {
	let fx = fixture!();
	let email = address("reauth-pw");
	let mut browser = Browser::default();
	let up = fx
		.post(
			"/auth/password/signup",
			ORIGIN,
			json!({ "email": email, "password": "correct horse battery", "verify": false, "turnstileToken": "human" }),
			&mut browser,
		)
		.await;
	assert_eq!(up.status, StatusCode::OK, "{:?}", up.body);

	let wrong = fx.post("/auth/reauth/password", ORIGIN, json!({ "password": "not the password" }), &mut browser).await;
	assert_eq!((wrong.status, wrong.body), (StatusCode::UNAUTHORIZED, json!({ "error": "invalid_credentials" })));

	let right = fx.post("/auth/reauth/password", ORIGIN, json!({ "password": "correct horse battery" }), &mut browser).await;
	assert_eq!(right.status, StatusCode::OK, "{:?}", right.body);
	assert_eq!(right.body["authTime"], access_claims(&browser)["auth_time"]);

	// Another account's password, presented in this session, is not this account's proof.
	let other = address("reauth-pw-other");
	let mut stranger = Browser::default();
	fx.post(
		"/auth/password/signup",
		ORIGIN,
		json!({ "email": other, "password": "another long password", "verify": false, "turnstileToken": "human" }),
		&mut stranger,
	)
	.await;
	let crossed = fx.post("/auth/reauth/password", ORIGIN, json!({ "password": "another long password" }), &mut browser).await;
	assert_eq!(crossed.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unverified_address_cannot_be_the_proof() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.post(
		"/auth/password/signup",
		ORIGIN,
		json!({ "email": address("reauth-unverified"), "password": "correct horse battery", "verify": false, "turnstileToken": "human" }),
		&mut browser,
	)
	.await;
	let asked = fx.reauth_code(&mut browser).await;
	assert_eq!((asked.status, asked.body), (StatusCode::FORBIDDEN, json!({ "error": "email_unverified" })));
	let spent = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": "000000" }), &mut browser).await;
	assert_eq!((spent.status, spent.body), (StatusCode::FORBIDDEN, json!({ "error": "email_unverified" })));
}

#[tokio::test]
async fn it_needs_a_session_and_the_csrf_token() {
	let fx = fixture!();
	let anonymous = fx.post("/auth/reauth/password", ORIGIN, json!({ "password": "x" }), &mut Browser::default()).await;
	assert_eq!((anonymous.status, anonymous.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));

	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("reauth-csrf"), &mut browser).await;
	let forged = fx.send(Method::POST, "/auth/reauth/passkey/options", ORIGIN, Some(json!({})), &mut browser, false).await;
	assert_eq!((forged.status, forged.body), (StatusCode::FORBIDDEN, json!({ "error": "csrf" })));
}

#[tokio::test]
async fn attempts_are_rate_limited_per_account() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("reauth-limit"), &mut browser).await;
	for _ in 0..concierge::web::REAUTH_ATTEMPTS_PER_WINDOW {
		let refused = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "no_passkey" })));
	}
	let throttled = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
	assert_eq!((throttled.status, throttled.body), (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "throttled" })));
	let also_codes = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": "000000" }), &mut browser).await;
	assert_eq!(also_codes.status, StatusCode::TOO_MANY_REQUESTS, "one budget across the methods");
}

mod passkeys {
	use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
	use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

	use super::*;

	fn origin() -> Url {
		Url::parse(ORIGIN).unwrap()
	}

	/// Register a passkey on the signed-in `browser`, returning the device that holds it.
	async fn register(fx: &Surface, browser: &mut Browser) -> WebauthnAuthenticator<SoftPasskey> {
		let begun = fx.post("/auth/passkey/register/options", ORIGIN, json!({}), browser).await;
		let mut options = begun.body["options"].clone();
		// The soft authenticator keeps no resident keys; the test plays a platform one.
		options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(false);
		let ccr: CreationChallengeResponse = serde_json::from_value(options).unwrap();
		let mut device = WebauthnAuthenticator::new(SoftPasskey::new(true));
		let credential = device.do_registration(origin(), ccr).expect("the authenticator registers");
		let done = fx
			.post(
				"/auth/passkey/register/verify",
				ORIGIN,
				json!({ "ceremony": begun.body["ceremony"], "credential": credential, "name": "Test key" }),
				browser,
			)
			.await;
		assert_eq!(done.body, json!({ "ok": true }));
		device
	}

	#[tokio::test]
	async fn an_assertion_by_the_accounts_own_passkey_moves_auth_time() {
		let fx = fixture!();
		let mut browser = Browser::default();
		fx.sign_in_with_code(&address("reauth-passkey"), &mut browser).await;
		let mut device = register(&fx, &mut browser).await;
		let before = access_claims(&browser);

		let begun = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		let rcr: RequestChallengeResponse = serde_json::from_value(begun.body["options"].clone()).unwrap();
		let credential = device.do_authentication(origin(), rcr).expect("the authenticator asserts");
		let done = fx
			.post(
				"/auth/reauth/passkey/verify",
				ORIGIN,
				json!({ "ceremony": begun.body["ceremony"], "credential": credential }),
				&mut browser,
			)
			.await;
		assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
		let after = access_claims(&browser);
		assert_ne!(after["jti"], before["jti"]);
		assert_eq!(done.body["authTime"], after["auth_time"]);

		let replay = fx
			.post(
				"/auth/reauth/passkey/verify",
				ORIGIN,
				json!({ "ceremony": begun.body["ceremony"], "credential": credential }),
				&mut browser,
			)
			.await;
		assert_eq!(
			(replay.status, replay.body),
			(StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })),
			"a ceremony is spent once"
		);
	}

	#[tokio::test]
	async fn changing_passkeys_needs_a_fresh_auth_time_that_re_auth_restores() {
		let fx = fixture!();
		let email = address("reauth-fresh");
		let mut browser = Browser::default();
		fx.sign_in_with_code(&email, &mut browser).await;
		register(&fx, &mut browser).await;
		if !common::web::age_session(&browser, 3600).await {
			return;
		}
		let stale = fx.post("/auth/passkey/register/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!((stale.status, stale.body), (StatusCode::FORBIDDEN, json!({ "error": "reauth_required" })));
		let methods = fx.get("/auth/methods", &mut browser).await;
		let credential_id = methods.body["passkeys"][0]["id"].as_str().unwrap().to_owned();
		let removed = fx.post("/auth/passkey/remove", ORIGIN, json!({ "credentialId": credential_id }), &mut browser).await;
		assert_eq!((removed.status, removed.body), (StatusCode::FORBIDDEN, json!({ "error": "reauth_required" })));

		// A passkey registered in this very session is not a way back; a mailed code is.
		fx.reauth_code(&mut browser).await;
		let code = fx.own_code(&email).await;
		let done = fx.post("/auth/reauth/code/verify", ORIGIN, json!({ "code": code }), &mut browser).await;
		assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
		let again = fx.post("/auth/passkey/register/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
	}

	#[tokio::test]
	async fn a_passkey_planted_after_the_session_began_does_not_re_authenticate() {
		let fx = fixture!();
		let email = address("reauth-planted");
		let mut browser = Browser::default();
		fx.sign_in_with_code(&email, &mut browser).await;
		let mut device = register(&fx, &mut browser).await;
		let user: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1").bind(&email).fetch_one(&fx.pool).await.unwrap();

		// Offered while the passkey still counts as older than the session...
		let begun = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		let rcr: RequestChallengeResponse = serde_json::from_value(begun.body["options"].clone()).unwrap();
		let credential = device.do_authentication(origin(), rcr).unwrap();
		// ...then made to look planted after it.
		sqlx::query("UPDATE passkey_credentials SET created_at = created_at + 100000 WHERE user_id = $1")
			.bind(user)
			.execute(&fx.pool)
			.await
			.unwrap();

		let refused = fx
			.post(
				"/auth/reauth/passkey/verify",
				ORIGIN,
				json!({ "ceremony": begun.body["ceremony"], "credential": credential }),
				&mut browser,
			)
			.await;
		assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "passkey_rejected" })));
		let none = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut browser).await;
		assert_eq!((none.status, none.body), (StatusCode::BAD_REQUEST, json!({ "error": "no_passkey" })), "it is not even offered");
	}

	#[tokio::test]
	async fn another_accounts_ceremony_is_not_taken() {
		let fx = fixture!();
		let mut owner = Browser::default();
		fx.sign_in_with_code(&address("reauth-pk-owner"), &mut owner).await;
		let mut device = register(&fx, &mut owner).await;
		let begun = fx.post("/auth/reauth/passkey/options", ORIGIN, json!({}), &mut owner).await;
		let rcr: RequestChallengeResponse = serde_json::from_value(begun.body["options"].clone()).unwrap();
		let credential = device.do_authentication(origin(), rcr).unwrap();

		let mut other = Browser::default();
		fx.sign_in_with_code(&address("reauth-pk-other"), &mut other).await;
		let refused = fx
			.post(
				"/auth/reauth/passkey/verify",
				ORIGIN,
				json!({ "ceremony": begun.body["ceremony"], "credential": credential }),
				&mut other,
			)
			.await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })));
	}
}
