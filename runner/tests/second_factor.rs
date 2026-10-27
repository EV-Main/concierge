//! The account's second factors (`/auth/second-factor/*`): enrolled, proven, removed and
//! recovered through the router a browser reaches, over a real Postgres and Redis. The
//! authenticator app is played by RFC 6238 computed here, from the secret the offer shows.

mod common;

use axum::http::StatusCode;
use common::{
	factor::{app_code, error, refusal, wrong},
	web::{Browser, ORIGIN, address, surface, surface_with_second_factor},
};
use serde_json::{Value, json};

macro_rules! fixture {
	() => {
		match surface_with_second_factor(None).await {
			Some(fx) => fx,
			None => return,
		}
	};
}

#[tokio::test]
async fn an_authenticator_is_enrolled_with_its_first_code_and_listed_without_its_secret() {
	let fx = fixture!();
	let mut who = fx.holder("sf-enrol").await;
	assert_eq!(who.recovery.len(), 10, "the first factor comes with its recovery codes");
	let methods = fx.get("/auth/methods", &mut who.browser).await;
	let held = &methods.body["secondFactor"];
	assert_eq!(held["recoveryCodesLeft"], 10);
	assert_eq!(held["factors"].as_array().unwrap().len(), 1);
	assert_eq!((held["factors"][0]["kind"].as_str(), held["factors"][0]["label"].as_str()), (Some("totp"), Some("Phone")));
	assert!(!methods.body.to_string().contains(&who.secret), "the secret is shown once, at enrolment");
	assert_eq!(fx.notices(&who.email).await, ["factor_added"]);
}

#[tokio::test]
async fn the_offer_is_an_otpauth_uri_for_the_secret_it_shows() {
	let fx = fixture!();
	let (mut browser, email) = fx.signed_in("sf-offer").await;
	let started = fx.enrol_start(&mut browser).await;
	let uri = started.body["offer"]["uri"].as_str().unwrap();
	let secret = started.body["offer"]["secret"].as_str().unwrap();
	assert!(uri.starts_with("otpauth://totp/EV%20Investment%3A"), "{uri}");
	assert!(uri.contains(&format!("secret={secret}&")), "{uri}");
	assert!(uri.contains(&form_urlencoded::byte_serialize(email.as_bytes()).collect::<String>()), "{uri}");
}

#[tokio::test]
async fn a_wrong_first_code_confirms_nothing() {
	let fx = fixture!();
	let (mut browser, _) = fx.signed_in("sf-wrong-first").await;
	let started = fx.enrol_start(&mut browser).await;
	let secret = started.body["offer"]["secret"].as_str().unwrap();
	let confirmed = fx
		.post(
			"/auth/second-factor/enrol/confirm",
			ORIGIN,
			json!({ "enrolment": started.body["enrolment"], "response": { "code": wrong(secret) } }),
			&mut browser,
		)
		.await;
	assert_eq!(refusal(&confirmed), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	let methods = fx.get("/auth/methods", &mut browser).await;
	assert_eq!(methods.body["secondFactor"]["factors"], json!([]));
}

#[tokio::test]
async fn a_code_is_accepted_once() {
	let fx = fixture!();
	let mut who = fx.holder("sf-replay").await;
	let enrolled_with = app_code(&who.secret, 0);
	let replayed = fx.prove(&mut who, &enrolled_with).await;
	assert_eq!(refusal(&replayed), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	let next = app_code(&who.secret.clone(), 1);
	assert_eq!(fx.prove(&mut who, &next).await.body, json!({ "ok": true }));
	assert_eq!(refusal(&fx.prove(&mut who, &next).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
}

#[tokio::test]
async fn five_wrong_answers_lock_every_answer_of_the_account() {
	let fx = fixture!();
	let mut who = fx.holder("sf-lock").await;
	let bad = wrong(&who.secret);
	for _ in 0..4 {
		assert_eq!(refusal(&fx.prove(&mut who, &bad).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	}
	// The fifth wrong answer is a recovery code: one count for every way in.
	let guessed = fx.post("/auth/second-factor/recover", ORIGIN, json!({ "code": "aaaa-aaaa-aaaa-aaaa" }), &mut who.browser).await;
	assert_eq!(refusal(&guessed), error(StatusCode::BAD_REQUEST, "invalid_code"));
	let right = app_code(&who.secret.clone(), 1);
	assert_eq!(refusal(&fx.prove(&mut who, &right).await), error(StatusCode::TOO_MANY_REQUESTS, "factor_locked"));
	let recovery = who.recovery[0].clone();
	let locked = fx.post("/auth/second-factor/recover", ORIGIN, json!({ "code": recovery }), &mut who.browser).await;
	assert_eq!(refusal(&locked), error(StatusCode::TOO_MANY_REQUESTS, "factor_locked"));
	let left: i64 = sqlx::query_scalar("SELECT count(*) FROM second_factor_recovery_codes WHERE user_id = $1 AND used_at IS NULL")
		.bind(who.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(left, 10, "a locked account spends no code");
}

#[tokio::test]
async fn the_count_is_kept_in_the_database_for_every_replica() {
	let fx = fixture!();
	let mut who = fx.holder("sf-replicas").await;
	let other = surface_with_second_factor(None).await.unwrap();
	let bad = wrong(&who.secret);
	for _ in 0..5 {
		fx.prove(&mut who, &bad).await;
	}
	// The second surface holds its own ceremonies and limiters, and no memory of the five.
	let options = other.post("/auth/second-factor/verify/options", ORIGIN, json!({}), &mut who.browser).await;
	let right = app_code(&who.secret, 1);
	let answered = other
		.post(
			"/auth/second-factor/verify",
			ORIGIN,
			json!({ "ceremony": options.body["ceremony"], "factor": who.factor, "response": { "code": right } }),
			&mut who.browser,
		)
		.await;
	assert_eq!(refusal(&answered), error(StatusCode::TOO_MANY_REQUESTS, "factor_locked"));
}

#[tokio::test]
async fn with_a_factor_a_fresh_sign_in_alone_changes_no_factor() {
	let fx = fixture!();
	let mut who = fx.holder("sf-fresh").await;
	// The session signed in moments ago: as fresh as a sign-in gets, and not enough.
	assert_eq!(refusal(&fx.enrol_start(&mut who.browser).await), error(StatusCode::FORBIDDEN, "second_factor_required"));
	let factor = who.factor.clone();
	let removed = fx.post("/auth/second-factor/remove", ORIGIN, json!({ "factor": factor }), &mut who.browser).await;
	assert_eq!(refusal(&removed), error(StatusCode::FORBIDDEN, "second_factor_required"));
	let regenerated = fx.post("/auth/second-factor/recovery-codes", ORIGIN, json!({}), &mut who.browser).await;
	assert_eq!(refusal(&regenerated), error(StatusCode::FORBIDDEN, "second_factor_required"));

	let next = app_code(&who.secret.clone(), 1);
	assert_eq!(fx.prove(&mut who, &next).await.body, json!({ "ok": true }));
	assert_eq!(fx.enrol_start(&mut who.browser).await.status, StatusCode::OK);
	let regenerated = fx.post("/auth/second-factor/recovery-codes", ORIGIN, json!({}), &mut who.browser).await;
	assert_eq!(regenerated.body["recoveryCodes"].as_array().unwrap().len(), 10);
	assert!(
		!regenerated.body["recoveryCodes"]
			.as_array()
			.unwrap()
			.iter()
			.any(|c| who.recovery.contains(&c.as_str().unwrap().to_owned()))
	);
}

#[tokio::test]
async fn a_second_factor_is_enrolled_only_for_a_verified_address() {
	let fx = fixture!();
	let mut browser = Browser::default();
	fx.post(
		"/auth/password/signup",
		ORIGIN,
		json!({ "email": address("sf-unverified"), "password": "correct horse battery", "verify": false, "turnstileToken": "human" }),
		&mut browser,
	)
	.await;
	assert_eq!(refusal(&fx.enrol_start(&mut browser).await), error(StatusCode::FORBIDDEN, "email_unverified"));
}

#[tokio::test]
async fn the_first_factor_wants_a_fresh_sign_in() {
	let fx = fixture!();
	let (mut browser, _) = fx.signed_in("sf-stale").await;
	if !common::web::age_session(&browser, 3600).await {
		return;
	}
	assert_eq!(refusal(&fx.enrol_start(&mut browser).await), error(StatusCode::FORBIDDEN, "reauth_required"));
}

#[tokio::test]
async fn the_last_factor_takes_the_recovery_codes_with_it() {
	let fx = fixture!();
	let mut who = fx.holder("sf-remove").await;
	let next = app_code(&who.secret.clone(), 1);
	fx.prove(&mut who, &next).await;
	let factor = who.factor.clone();
	let removed = fx.post("/auth/second-factor/remove", ORIGIN, json!({ "factor": factor }), &mut who.browser).await;
	assert_eq!(removed.body, json!({ "ok": true, "remaining": 0 }));
	let methods = fx.get("/auth/methods", &mut who.browser).await;
	assert_eq!(methods.body["secondFactor"], json!({ "factors": [], "recoveryCodesLeft": 0 }));
	let options = fx.post("/auth/second-factor/verify/options", ORIGIN, json!({}), &mut who.browser).await;
	assert_eq!(refusal(&options), error(StatusCode::CONFLICT, "no_second_factor"));
	assert_eq!(fx.notices(&who.email).await, ["factor_added", "factor_removed"]);
}

#[tokio::test]
async fn a_recovery_code_removes_every_factor_and_ends_every_session() {
	let fx = fixture!();
	let mut who = fx.holder("sf-recover").await;
	let mut elsewhere = Browser::default();
	fx.sign_in_with_code(&who.email, &mut elsewhere).await;
	let version: i64 = sqlx::query_scalar("SELECT token_version FROM users WHERE id = $1")
		.bind(who.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();

	let typed = who.recovery[3].to_ascii_uppercase().replace('-', " ");
	let recovered = fx.post("/auth/second-factor/recover", ORIGIN, json!({ "code": typed }), &mut who.browser).await;
	assert_eq!(recovered.body, json!({ "ok": true }));

	let after: i64 = sqlx::query_scalar("SELECT token_version FROM users WHERE id = $1")
		.bind(who.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(after, version + 1);
	let revoked: i64 = sqlx::query_scalar("SELECT count(*) FROM user_outbox WHERE user_id = $1 AND kind = 'SESSIONS_REVOKED'")
		.bind(who.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(revoked, 1, "the money plane learns every session ended");
	let left: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM second_factors WHERE user_id = $1) + (SELECT count(*) FROM second_factor_recovery_codes WHERE user_id = $1)")
		.bind(who.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	assert_eq!(left, 0);
	assert_eq!(fx.get("/auth/methods", &mut who.browser).await.status, StatusCode::UNAUTHORIZED);
	assert_eq!(fx.get("/auth/methods", &mut elsewhere).await.status, StatusCode::UNAUTHORIZED);
	assert_eq!(fx.notices(&who.email).await, ["factor_added", "recovered"]);
}

#[tokio::test]
async fn sealed_material_opens_only_on_its_own_row() {
	let fx = fixture!();
	let mut a = fx.holder("sf-seal-a").await;
	let mut b = fx.holder("sf-seal-b").await;
	let material: Vec<u8> = sqlx::query_scalar("SELECT material FROM second_factors WHERE user_id = $1")
		.bind(a.user)
		.fetch_one(&fx.pool)
		.await
		.unwrap();
	let secret = data_encoding::BASE32_NOPAD.decode(a.secret.as_bytes()).unwrap();
	assert!(!material.windows(secret.len()).any(|w| w == secret.as_slice()), "the secret is not at rest in the clear");
	sqlx::query("UPDATE second_factors SET material = $2 WHERE user_id = $1")
		.bind(b.user)
		.bind(&material)
		.execute(&fx.pool)
		.await
		.unwrap();
	let crossed = fx.post("/auth/second-factor/verify/options", ORIGIN, json!({}), &mut b.browser).await;
	assert_eq!(refusal(&crossed), error(StatusCode::INTERNAL_SERVER_ERROR, "internal"), "a moved blob is refused, never read");
	let a_code = app_code(&a.secret, 1);
	assert_eq!(fx.prove(&mut a, &a_code).await.body, json!({ "ok": true }));
}

#[tokio::test]
async fn the_routes_take_only_this_origin_and_the_csrf_token() {
	let fx = fixture!();
	let (mut browser, _) = fx.signed_in("sf-origin").await;
	let foreign = fx
		.post(
			"/auth/second-factor/enrol/start",
			"https://invest.evinvest.ltd",
			json!({ "kind": "totp", "label": "Phone" }),
			&mut browser,
		)
		.await;
	assert_eq!(refusal(&foreign), error(StatusCode::FORBIDDEN, "origin"));
	let no_csrf = fx
		.send(
			axum::http::Method::POST,
			"/auth/second-factor/enrol/start",
			ORIGIN,
			Some(json!({ "kind": "totp", "label": "Phone" })),
			&mut browser,
			false,
		)
		.await;
	assert_eq!(refusal(&no_csrf), error(StatusCode::FORBIDDEN, "csrf"));
	let unknown_kind = fx.post("/auth/second-factor/enrol/start", ORIGIN, json!({ "kind": "sms", "label": "Phone" }), &mut browser).await;
	assert_eq!(refusal(&unknown_kind), error(StatusCode::BAD_REQUEST, "invalid_kind"));
}

#[tokio::test]
async fn without_a_seal_key_nothing_is_mounted() {
	let Some(fx) = surface().await else {
		return;
	};
	let (mut browser, _) = fx.signed_in("sf-unmounted").await;
	assert_eq!(fx.enrol_start(&mut browser).await.status, StatusCode::NOT_FOUND);
	assert_eq!(fx.get("/auth/methods", &mut browser).await.body["secondFactor"], Value::Null);
}

#[tokio::test]
async fn a_body_that_does_not_read_is_refused_in_the_surface_shape() {
	let fx = fixture!();
	let mut who = fx.holder("sf-body").await;
	for body in [json!({ "factor": "not-a-uuid" }), json!({}), json!({ "factor": who.factor, "extra": true })] {
		let answer = fx.post("/auth/second-factor/remove", ORIGIN, body.clone(), &mut who.browser).await;
		assert_eq!(refusal(&answer), error(StatusCode::BAD_REQUEST, "invalid_request"), "{body}");
	}
}
