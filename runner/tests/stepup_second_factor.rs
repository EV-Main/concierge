//! Step-up by a second factor: a trusted host's page asks the account to answer one of its
//! factors for the hash of ONE operation and gets a proof that says how much assurance the
//! answer gave and never which factor gave it — through the router a browser reaches, over
//! a real Postgres and Redis.

mod common;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
	factor::{Holder, app_code, error, refusal, wrong},
	web::{Answer, Browser, ORIGIN, Surface, surface_with_second_factor},
};
use concierge::web::stepup::StepupDeps;
use evconcierge_auth::{
	jwks::JwksCache,
	stepup::{Aal, Expected, StepupError, verify_stepup_proof},
};
use evconcierge_contracts::concierge::v1::Jwk;
use serde_json::{Value, json};

const SA: &str = "https://sa.evinvest.test";
const INVEST: &str = "https://invest.evinvest.test";
const ISSUER: &str = "https://auth.concierge.test";
/// The public half of `common::signing_auth`'s throwaway key.
const JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
const HASH_A: [u8; 32] = [0xaa; 32];
const HASH_B: [u8; 32] = [0xbb; 32];

macro_rules! fixture {
	() => {
		match surface_with_second_factor(Some(StepupDeps {
			origins: vec![SA.into(), INVEST.into()],
			ttl_secs: 120,
		}))
		.await
		{
			Some(fx) => fx,
			None => return,
		}
	};
}

fn hex(hash: &[u8; 32]) -> String {
	hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn jwks() -> JwksCache {
	JwksCache::from_wire(&[Jwk {
		kid: "test-kid".into(),
		kty: "OKP".into(),
		crv: "Ed25519".into(),
		x: JWK_X.into(),
		alg: "EdDSA".into(),
		r#use: "sig".into(),
	}])
	.unwrap()
}

fn expected<'a>(who: &'a str, origin: &'a str, hash: &'a [u8; 32]) -> Expected<'a> {
	Expected {
		intent_hash: hash,
		sub: who,
		origin,
		min_aal: Aal::SECOND_FACTOR,
	}
}

impl Surface {
	async fn options(&self, from: &str, hash: &[u8; 32], min_aal: u8, browser: &mut Browser) -> Answer {
		self.page_post("/auth/stepup/options", from, json!({ "intent_hash": hex(hash), "min_aal": min_aal }), browser)
			.await
	}

	/// Ask for a proof of `hash` from `from` and answer `code` to the holder's factor.
	async fn step_up(&self, who: &mut Holder, from: &str, hash: &[u8; 32], code: &str) -> Answer {
		let begun = self.options(from, hash, 2, &mut who.browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		self.page_post(
			"/auth/stepup/verify",
			from,
			json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code } }),
			&mut who.browser,
		)
		.await
	}
}

#[tokio::test]
async fn an_answered_factor_proves_one_operation_and_the_proof_names_no_factor() {
	let fx = fixture!();
	let mut who = fx.holder("su-proof").await;
	let begun = fx.options(INVEST, &HASH_A, 2, &mut who.browser).await;
	assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
	assert_eq!(begun.body["factors"].as_array().unwrap().len(), 1);
	assert_eq!(
		(begun.body["factors"][0]["id"].as_str(), begun.body["factors"][0]["kind"].as_str()),
		(Some(who.factor.as_str()), Some("totp"))
	);

	let code = app_code(&who.secret, 1);
	let done = fx
		.page_post(
			"/auth/stepup/verify",
			INVEST,
			json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code } }),
			&mut who.browser,
		)
		.await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	assert_eq!(done.body["aal"], 2);
	let proof = done.body["proof"].as_str().unwrap();
	let sub = who.user.to_string();
	let claims = verify_stepup_proof(proof, &jwks(), ISSUER, &expected(&sub, INVEST, &HASH_A)).expect("a proof for this operation");
	assert_eq!(claims.aal, Aal::SECOND_FACTOR);
	assert_eq!(
		verify_stepup_proof(proof, &jwks(), ISSUER, &expected(&sub, INVEST, &HASH_B)).unwrap_err(),
		StepupError::Mismatch("operation")
	);
	assert_eq!(
		verify_stepup_proof(proof, &jwks(), ISSUER, &expected(&sub, SA, &HASH_A)).unwrap_err(),
		StepupError::Mismatch("origin")
	);

	let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(proof.split('.').nth(1).unwrap()).unwrap()).unwrap();
	let mut keys: Vec<&str> = payload.as_object().unwrap().keys().map(String::as_str).collect();
	keys.sort_unstable();
	assert_eq!(keys, ["aal", "aud", "exp", "iat", "intent_hash", "iss", "jti", "origin", "sub", "typ"]);
	let wire = payload.to_string();
	assert!(!wire.contains("totp") && !wire.contains(&who.factor), "the bank learns no kind and no factor: {wire}");
}

#[tokio::test]
async fn an_account_without_a_factor_is_told_so() {
	let fx = fixture!();
	let (mut browser, _) = fx.signed_in("su-none").await;
	assert_eq!(refusal(&fx.options(INVEST, &HASH_A, 2, &mut browser).await), error(StatusCode::CONFLICT, "no_second_factor"));
}

#[tokio::test]
async fn a_level_no_factor_of_the_account_gives_finds_none_and_a_level_below_a_second_factor_is_no_level() {
	let fx = fixture!();
	let mut who = fx.holder("su-level").await;
	assert_eq!(refusal(&fx.options(INVEST, &HASH_A, 3, &mut who.browser).await), error(StatusCode::CONFLICT, "no_second_factor"));
	assert_eq!(refusal(&fx.options(INVEST, &HASH_A, 1, &mut who.browser).await), error(StatusCode::BAD_REQUEST, "invalid_aal"));
}

#[tokio::test]
async fn a_method_and_a_level_together_are_refused() {
	let fx = fixture!();
	let mut who = fx.holder("su-both").await;
	let both = fx
		.page_post(
			"/auth/stepup/options",
			INVEST,
			json!({ "intent_hash": hex(&HASH_A), "min_aal": 2, "method": "passkey" }),
			&mut who.browser,
		)
		.await;
	assert_eq!(refusal(&both), error(StatusCode::BAD_REQUEST, "invalid_request"));
}

#[tokio::test]
async fn a_code_that_proved_one_operation_proves_no_other() {
	let fx = fixture!();
	let mut who = fx.holder("su-replay").await;
	let code = app_code(&who.secret, 1);
	assert_eq!(fx.step_up(&mut who, INVEST, &HASH_A, &code).await.status, StatusCode::OK);
	assert_eq!(refusal(&fx.step_up(&mut who, INVEST, &HASH_B, &code).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
}

#[tokio::test]
async fn wrong_answers_here_lock_the_account_everywhere() {
	let fx = fixture!();
	let mut who = fx.holder("su-lock").await;
	let bad = wrong(&who.secret);
	for _ in 0..3 {
		assert_eq!(refusal(&fx.step_up(&mut who, INVEST, &HASH_A, &bad).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	}
	for _ in 0..2 {
		assert_eq!(refusal(&fx.prove(&mut who, &bad).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	}
	let right = app_code(&who.secret, 1);
	assert_eq!(
		refusal(&fx.step_up(&mut who, INVEST, &HASH_A, &right).await),
		error(StatusCode::TOO_MANY_REQUESTS, "factor_locked")
	);
	assert_eq!(refusal(&fx.prove(&mut who, &right).await), error(StatusCode::TOO_MANY_REQUESTS, "factor_locked"));
}

/// The account's guard is what bounds guessing; the page's request budget sits above it, so
/// a reader who keeps trying is told the lock, not to slow down.
#[tokio::test]
async fn the_guard_locks_before_the_request_budget_runs_out() {
	let fx = fixture!();
	let mut who = fx.holder("su-budget").await;
	let bad = wrong(&who.secret);
	for _ in 0..5 {
		assert_eq!(refusal(&fx.step_up(&mut who, INVEST, &HASH_A, &bad).await), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	}
	let right = app_code(&who.secret, 1);
	assert_eq!(
		refusal(&fx.step_up(&mut who, INVEST, &HASH_A, &right).await),
		error(StatusCode::TOO_MANY_REQUESTS, "factor_locked")
	);
}

#[tokio::test]
async fn a_ceremony_is_its_page_and_its_account_and_one_answer() {
	let fx = fixture!();
	let mut who = fx.holder("su-ceremony").await;
	let begun = fx.options(INVEST, &HASH_A, 2, &mut who.browser).await;
	let answer = |code: String| json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code } });
	let elsewhere = fx.page_post("/auth/stepup/verify", SA, answer(app_code(&who.secret, 1)), &mut who.browser).await;
	assert_eq!(refusal(&elsewhere), error(StatusCode::BAD_REQUEST, "ceremony_expired"), "another page cannot finish it");

	let begun = fx.options(INVEST, &HASH_A, 2, &mut who.browser).await;
	let body = |code: String| json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code } });
	let mut stranger = fx.holder("su-stranger").await;
	let theirs = fx.page_post("/auth/stepup/verify", INVEST, body(app_code(&who.secret, 1)), &mut stranger.browser).await;
	assert_eq!(refusal(&theirs), error(StatusCode::BAD_REQUEST, "ceremony_expired"), "another account cannot finish it");

	let begun = fx.options(INVEST, &HASH_A, 2, &mut who.browser).await;
	let body = |code: String| json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code } });
	let missed = fx.page_post("/auth/stepup/verify", INVEST, body(wrong(&who.secret)), &mut who.browser).await;
	assert_eq!(refusal(&missed), error(StatusCode::BAD_REQUEST, "invalid_answer"));
	let again = fx.page_post("/auth/stepup/verify", INVEST, body(app_code(&who.secret, 1)), &mut who.browser).await;
	assert_eq!(refusal(&again), error(StatusCode::BAD_REQUEST, "ceremony_expired"), "one answer per ceremony");
}

#[tokio::test]
async fn an_account_ceremony_mints_no_proof_and_an_operation_ceremony_changes_no_factor() {
	let fx = fixture!();
	let mut who = fx.holder("su-purpose").await;
	let manage = fx.post("/auth/second-factor/verify/options", ORIGIN, json!({}), &mut who.browser).await;
	let as_proof = fx
		.page_post(
			"/auth/stepup/verify",
			INVEST,
			json!({ "ceremony_id": manage.body["ceremony"], "factor": who.factor, "response": { "code": app_code(&who.secret, 1) } }),
			&mut who.browser,
		)
		.await;
	assert_eq!(refusal(&as_proof), error(StatusCode::BAD_REQUEST, "ceremony_expired"));

	let code = app_code(&who.secret, 1);
	assert_eq!(fx.step_up(&mut who, INVEST, &HASH_A, &code).await.status, StatusCode::OK);
	assert_eq!(
		refusal(&fx.enrol_start(&mut who.browser).await),
		error(StatusCode::FORBIDDEN, "second_factor_required"),
		"a proof for an operation does not open the account's factors"
	);
	let operation = fx.options(INVEST, &HASH_B, 2, &mut who.browser).await;
	let as_manage = fx
		.post(
			"/auth/second-factor/verify",
			ORIGIN,
			json!({ "ceremony": operation.body["ceremony_id"], "factor": who.factor, "response": { "code": app_code(&who.secret, 0) } }),
			&mut who.browser,
		)
		.await;
	assert_eq!(refusal(&as_manage), error(StatusCode::BAD_REQUEST, "ceremony_expired"));
}
