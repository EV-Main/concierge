//! Step-up by a second factor: a trusted host's page asks the account to answer one of its
//! factors for the hash of ONE operation and gets a proof that says how much assurance the
//! answer gave and never which factor gave it — through the router a browser reaches, over
//! a real Postgres and Redis.

mod common;

use axum::{
	body::Body,
	http::{Method, Request, StatusCode, header},
};
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
use tower::ServiceExt;

const SA: &str = "https://sa.evinvest.test";
const INVEST: &str = "https://invest.evinvest.test";
const ISSUER: &str = "https://auth.concierge.test";
/// The public half of `common::signing_auth`'s throwaway key.
const JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
const HASH_A: [u8; 32] = [0xaa; 32];
const HASH_B: [u8; 32] = [0xbb; 32];

macro_rules! fixture {
	() => {
		fixture!(120)
	};
	($ttl:expr) => {
		match surface_with_second_factor(Some(StepupDeps {
			origins: vec![SA.into(), INVEST.into()],
			ttl_secs: $ttl,
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

/// What a browser's `fetch` from a page would put on the wire.
struct Wire<'a> {
	path: &'a str,
	origin: Option<&'a str>,
	site: Option<&'a str>,
	content_type: Option<&'a str>,
	body: String,
}

impl<'a> Wire<'a> {
	fn post(path: &'a str, origin: &'a str, body: Value) -> Self {
		Self {
			path,
			origin: Some(origin),
			site: Some("same-site"),
			content_type: Some("application/json"),
			body: body.to_string(),
		}
	}
}

impl Surface {
	async fn wire(&self, wire: Wire<'_>, browser: &mut Browser) -> Answer {
		let mut request = Request::builder().method(Method::POST).uri(wire.path);
		if let Some(origin) = wire.origin {
			request = request.header(header::ORIGIN, origin);
		}
		if let Some(site) = wire.site {
			request = request.header("sec-fetch-site", site);
		}
		if let Some(ct) = wire.content_type {
			request = request.header(header::CONTENT_TYPE, ct);
		}
		if !browser.cookies.is_empty() {
			request = request.header(header::COOKIE, browser.header());
		}
		let response = self.router.clone().oneshot(request.body(Body::from(wire.body)).unwrap()).await.unwrap();
		browser.absorb(response.headers());
		let (status, headers) = (response.status(), response.headers().clone());
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
		Answer {
			status,
			headers,
			body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
		}
	}

	async fn preflight(&self, origin: &str, path: &str, browser: &mut Browser) -> Answer {
		let request = Request::builder()
			.method(Method::OPTIONS)
			.uri(path)
			.header(header::ORIGIN, origin)
			.header("access-control-request-method", "POST")
			.header("access-control-request-headers", "content-type")
			.header("sec-fetch-site", "same-site")
			.body(Body::empty())
			.unwrap();
		let response = self.router.clone().oneshot(request).await.unwrap();
		browser.absorb(response.headers());
		Answer {
			status: response.status(),
			headers: response.headers().clone(),
			body: Value::Null,
		}
	}

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
async fn only_a_level_and_a_factor_answer_parse() {
	let fx = fixture!();
	let mut who = fx.holder("su-shape").await;
	let hash = hex(&HASH_A);
	for body in [
		json!({ "intent_hash": hash, "min_aal": 2, "method": "passkey" }),
		json!({ "intent_hash": hash, "min_aal": 2, "password": "hunter2" }),
		json!({ "intent_hash": hash }),
	] {
		let refused = fx.page_post("/auth/stepup/options", INVEST, body.clone(), &mut who.browser).await;
		assert_eq!(refusal(&refused), error(StatusCode::BAD_REQUEST, "invalid_request"), "{body}");
	}
	let garbage = fx
		.wire(
			Wire {
				body: "{not json".into(),
				..Wire::post("/auth/stepup/options", INVEST, json!({}))
			},
			&mut who.browser,
		)
		.await;
	assert_eq!(
		refusal(&garbage),
		error(StatusCode::BAD_REQUEST, "invalid_request"),
		"a parse error is in the surface's own shape"
	);
	for bad in [hash.to_uppercase(), "aa".repeat(31), "aa".repeat(33), "zz".repeat(32), String::new()] {
		let refused = fx.page_post("/auth/stepup/options", INVEST, json!({ "intent_hash": bad, "min_aal": 2 }), &mut who.browser).await;
		assert_eq!(refusal(&refused), error(StatusCode::BAD_REQUEST, "invalid_intent"), "{bad:?}");
	}

	let begun = fx.options(INVEST, &HASH_A, 2, &mut who.browser).await;
	let code = app_code(&who.secret, 1);
	for body in [
		json!({ "ceremony_id": begun.body["ceremony_id"], "password": "hunter2" }),
		json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": code }, "code": code }),
	] {
		let refused = fx.page_post("/auth/stepup/verify", INVEST, body.clone(), &mut who.browser).await;
		assert_eq!(refusal(&refused), error(StatusCode::BAD_REQUEST, "invalid_request"), "{body}");
	}
	for path in ["/auth/stepup/password", "/auth/stepup/code/verify"] {
		let missing = fx.page_post(path, INVEST, json!({ "password": "x" }), &mut who.browser).await;
		assert!(matches!(missing.status, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED), "{path}: {:?}", missing.status);
	}
}

#[tokio::test]
async fn an_origin_that_is_not_listed_exactly_is_refused_and_cannot_read_the_answer() {
	let fx = fixture!();
	let mut who = fx.holder("su-origin").await;
	for rogue in [
		"https://rogue.evinvest.test",
		"https://evinvest.test",
		"https://evinvest.test.evil.example",
		"https://sa.evinvest.test.evil.example",
		"null",
		"",
		"https://sa.evinvest.test:8443",
		"https://sa.evinvest.test/",
		"https://sa.evinvest.test/wallet",
		"http://sa.evinvest.test",
		"https://SA.evinvest.test",
		"*",
	] {
		let refused = fx.options(rogue, &HASH_A, 2, &mut who.browser).await;
		assert_eq!(refusal(&refused), error(StatusCode::FORBIDDEN, "origin"), "origin {rogue:?}");
		assert!(refused.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(), "origin {rogue:?} may not read the refusal");
		let approval = fx.preflight(rogue, "/auth/stepup/options", &mut who.browser).await;
		assert!(approval.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(), "origin {rogue:?} gets no preflight approval");
	}
	let mut none = Wire::post("/auth/stepup/options", SA, json!({ "intent_hash": hex(&HASH_A), "min_aal": 2 }));
	none.origin = None;
	assert_eq!(refusal(&fx.wire(none, &mut who.browser).await), error(StatusCode::FORBIDDEN, "origin"));
}

#[tokio::test]
async fn the_preflight_of_a_listed_origin_is_approved_for_a_minute() {
	let fx = fixture!();
	let mut browser = Browser::default();
	for from in [SA, INVEST] {
		for path in ["/auth/stepup/options", "/auth/stepup/verify"] {
			let answer = fx.preflight(from, path, &mut browser).await;
			assert!(answer.status.is_success(), "{:?}", answer.status);
			let h = &answer.headers;
			assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], from);
			assert_eq!(h[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
			assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "60");
			assert_eq!(h[header::ACCESS_CONTROL_ALLOW_METHODS], "POST");
			assert!(h[header::VARY].to_str().unwrap().to_ascii_lowercase().contains("origin"));
		}
	}
}

#[tokio::test]
async fn fetch_metadata_and_content_type_are_enforced() {
	let fx = fixture!();
	let mut who = fx.holder("su-meta").await;
	let body = json!({ "intent_hash": hex(&HASH_A), "min_aal": 2 });
	for site in [None, Some("cross-site"), Some("none"), Some("")] {
		let mut wire = Wire::post("/auth/stepup/options", SA, body.clone());
		wire.site = site;
		assert_eq!(refusal(&fx.wire(wire, &mut who.browser).await), error(StatusCode::FORBIDDEN, "fetch_site"), "site {site:?}");
	}
	for same in ["same-origin", "same-site"] {
		let mut wire = Wire::post("/auth/stepup/options", SA, body.clone());
		wire.site = Some(same);
		assert_eq!(fx.wire(wire, &mut who.browser).await.status, StatusCode::OK, "{same}");
	}
	for ct in [
		None,
		Some("text/plain"),
		Some("text/plain;charset=UTF-8"),
		Some("application/x-www-form-urlencoded"),
		Some("multipart/form-data; boundary=x"),
	] {
		let mut wire = Wire::post("/auth/stepup/options", SA, body.clone());
		wire.content_type = ct;
		assert_eq!(
			refusal(&fx.wire(wire, &mut who.browser).await),
			error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "content_type"),
			"content type {ct:?}"
		);
	}
}

#[tokio::test]
async fn without_the_flag_nothing_is_mounted() {
	let Some(fx) = surface_with_second_factor(None).await else { return };
	let mut who = fx.holder("su-off").await;
	for path in ["/auth/stepup/options", "/auth/stepup/verify"] {
		assert_eq!(fx.page_post(path, SA, json!({}), &mut who.browser).await.status, StatusCode::NOT_FOUND, "{path}");
		let approval = fx.preflight(SA, path, &mut who.browser).await;
		assert!(approval.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
	}
}

#[tokio::test]
async fn it_needs_a_live_session() {
	let fx = fixture!();
	let mut anonymous = Browser::default();
	assert_eq!(refusal(&fx.options(SA, &HASH_A, 2, &mut anonymous).await), error(StatusCode::UNAUTHORIZED, "unauthenticated"));

	let mut who = fx.holder("su-revoked").await;
	sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
		.bind(who.user)
		.execute(&fx.pool)
		.await
		.unwrap();
	assert_eq!(refusal(&fx.options(SA, &HASH_A, 2, &mut who.browser).await), error(StatusCode::UNAUTHORIZED, "unauthenticated"));
}

#[tokio::test]
async fn asking_is_budgeted_per_account() {
	let fx = fixture!();
	let mut who = fx.holder("su-asks").await;
	let mut last = StatusCode::OK;
	for _ in 0..11 {
		last = fx.options(SA, &HASH_A, 2, &mut who.browser).await.status;
	}
	assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
	let mut stranger = fx.holder("su-asks-other").await;
	assert_eq!(fx.options(SA, &HASH_A, 2, &mut stranger.browser).await.status, StatusCode::OK, "another account has its own");
}

#[tokio::test]
async fn an_account_holds_at_most_three_ceremonies_and_evicts_its_own_oldest() {
	let fx = fixture!();
	let mut who = fx.holder("su-cap").await;
	let mut other = fx.holder("su-cap-other").await;
	let theirs = fx.options(SA, &HASH_B, 2, &mut other.browser).await;
	let mut ceremonies = Vec::new();
	for _ in 0..4 {
		let begun = fx.options(SA, &HASH_A, 2, &mut who.browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		ceremonies.push(begun.body["ceremony_id"].clone());
	}
	let answer = |ceremony: &Value, holder: &Holder| json!({ "ceremony_id": ceremony, "factor": holder.factor, "response": { "code": app_code(&holder.secret, 1) } });
	let oldest = fx.page_post("/auth/stepup/verify", SA, answer(&ceremonies[0], &who), &mut who.browser).await;
	assert_eq!(refusal(&oldest), error(StatusCode::BAD_REQUEST, "ceremony_expired"), "the fourth evicted the first");
	let newest = fx.page_post("/auth/stepup/verify", SA, answer(&ceremonies[3], &who), &mut who.browser).await;
	assert_eq!(newest.status, StatusCode::OK, "{:?}", newest.body);
	let kept = fx.page_post("/auth/stepup/verify", SA, answer(&theirs.body["ceremony_id"], &other), &mut other.browser).await;
	assert_eq!(kept.status, StatusCode::OK, "another account's ceremony was not evicted: {:?}", kept.body);
}

#[tokio::test]
async fn a_lapsed_ceremony_gives_no_proof() {
	let fx = fixture!(1);
	let mut who = fx.holder("su-lapsed").await;
	let begun = fx.options(SA, &HASH_A, 2, &mut who.browser).await;
	tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
	let late = fx
		.page_post(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "factor": who.factor, "response": { "code": app_code(&who.secret, 1) } }),
			&mut who.browser,
		)
		.await;
	assert_eq!(refusal(&late), error(StatusCode::BAD_REQUEST, "ceremony_expired"));
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
