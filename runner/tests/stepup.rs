//! Step-up bound to one operation (`/auth/stepup/*`): a trusted host's page asks the
//! signed-in account to confirm the hash of ONE operation and gets a proof for exactly that
//! hash — through the router a browser reaches, over a real Postgres and Redis.

mod common;

use axum::{
	body::Body,
	http::{Method, Request, StatusCode, header},
};
use common::web::{Answer, Browser, ORIGIN, Surface, address, surface, surface_with_stepup};
use concierge::web::stepup::StepupDeps;
use evconcierge_auth::{
	TokenType, VerifyPolicy,
	jwks::{JwksCache, verify_token},
	stepup::{
		StepupError,
		legacy::{MethodClaims, StepupMethod, verify_method_proof},
	},
};
use evconcierge_contracts::concierge::v1::Jwk;
use serde_json::{Value, json};
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

const SA: &str = "https://sa.evinvest.test";
const INVEST: &str = "https://invest.evinvest.test";
const ISSUER: &str = "https://auth.concierge.test";
/// The public half of `common::signing_auth`'s throwaway key.
const JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
const HASH_A: [u8; 32] = [0xaa; 32];
const HASH_B: [u8; 32] = [0xbb; 32];

fn hex(hash: &[u8; 32]) -> String {
	hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn deps(ttl_secs: u64) -> StepupDeps {
	StepupDeps {
		origins: vec![SA.into(), INVEST.into()],
		ttl_secs,
	}
}

async fn with_stepup(ttl_secs: u64) -> Option<Surface> {
	surface_with_stepup(Some(deps(ttl_secs))).await
}

macro_rules! fixture {
	() => {
		match with_stepup(120).await {
			Some(fx) => fx,
			None => return,
		}
	};
	($ttl:expr) => {
		match with_stepup($ttl).await {
			Some(fx) => fx,
			None => return,
		}
	};
}

/// What a browser's `fetch` from a page would put on the wire.
struct Wire<'a> {
	method: Method,
	path: &'a str,
	origin: Option<&'a str>,
	site: Option<&'a str>,
	content_type: Option<&'a str>,
	body: Option<String>,
}

impl<'a> Wire<'a> {
	fn post(path: &'a str, origin: &'a str, body: Value) -> Self {
		Self {
			method: Method::POST,
			path,
			origin: Some(origin),
			site: Some("same-site"),
			content_type: Some("application/json"),
			body: Some(body.to_string()),
		}
	}
}

impl Surface {
	async fn wire(&self, wire: Wire<'_>, browser: &mut Browser) -> Answer {
		let mut request = Request::builder().method(wire.method).uri(wire.path);
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
		let response = self.router.clone().oneshot(request.body(wire.body.map_or_else(Body::empty, Body::from)).unwrap()).await.unwrap();
		browser.absorb(response.headers());
		let (status, headers) = (response.status(), response.headers().clone());
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
		Answer {
			status,
			headers,
			body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
		}
	}

	async fn stepup(&self, path: &str, from: &str, body: Value, browser: &mut Browser) -> Answer {
		self.wire(Wire::post(path, from, body), browser).await
	}

	async fn begin(&self, from: &str, hash: &[u8; 32], browser: &mut Browser) -> Answer {
		self.stepup("/auth/stepup/options", from, json!({ "intent_hash": hex(hash), "method": "passkey" }), browser).await
	}
}

fn page(origin: &str) -> Url {
	Url::parse(origin).unwrap()
}

/// A signed-in browser holding a passkey that is older than its session.
struct Enrolled {
	browser: Browser,
	device: WebauthnAuthenticator<SoftPasskey>,
	email: String,
	user: uuid::Uuid,
}

async fn enrolled(fx: &Surface, tag: &str) -> Enrolled {
	let email = address(tag);
	let mut browser = Browser::default();
	fx.sign_in_with_code(&email, &mut browser).await;
	let begun = fx.post("/auth/passkey/register/options", ORIGIN, json!({}), &mut browser).await;
	let mut options = begun.body["options"].clone();
	// The soft authenticator keeps no resident keys; the test plays a platform one.
	options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(false);
	let ccr: CreationChallengeResponse = serde_json::from_value(options).unwrap();
	let mut device = WebauthnAuthenticator::new(SoftPasskey::new(true));
	let credential = device.do_registration(page(ORIGIN), ccr).expect("the authenticator registers");
	let done = fx
		.post(
			"/auth/passkey/register/verify",
			ORIGIN,
			json!({ "ceremony": begun.body["ceremony"], "credential": credential, "name": "Test key" }),
			&mut browser,
		)
		.await;
	assert_eq!(done.body, json!({ "ok": true }));
	let user: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1").bind(&email).fetch_one(&fx.pool).await.unwrap();
	// Registered in this very session, a key is as old as it: make it older, so the tests do
	// not hang on the second boundary.
	sqlx::query("UPDATE passkey_credentials SET created_at = created_at - 100000 WHERE user_id = $1")
		.bind(user)
		.execute(&fx.pool)
		.await
		.unwrap();
	Enrolled { browser, device, email, user }
}

impl Enrolled {
	fn assert(&mut self, from: &str, begun: &Answer) -> Value {
		let rcr: RequestChallengeResponse = serde_json::from_value(begun.body["options"].clone()).unwrap();
		serde_json::to_value(self.device.do_authentication(page(from), rcr).expect("the authenticator asserts")).unwrap()
	}
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

/// What the money plane pinned to `evconcierge_auth` 0.1 expects of these proofs.
struct Expect<'a> {
	sub: &'a str,
	origin: &'a str,
	hash: &'a [u8; 32],
}

fn expect<'a>(sub: &'a str, origin: &'a str, hash: &'a [u8; 32]) -> Expect<'a> {
	Expect { sub, origin, hash }
}

fn verify_stepup_proof(proof: &str, cache: &JwksCache, issuer: &str, expected: &Expect<'_>) -> Result<MethodClaims, StepupError> {
	verify_method_proof(
		proof,
		cache,
		issuer,
		expected.hash,
		expected.sub,
		expected.origin,
		&[StepupMethod::Passkey, StepupMethod::EmailCode],
	)
}

fn access_cookie_claims(browser: &Browser) -> Value {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	let token = browser.get("ev_access").expect("an access cookie");
	serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

async fn prove(fx: &Surface, who: &mut Enrolled, from: &str, hash: &[u8; 32]) -> Answer {
	let begun = fx.begin(from, hash, &mut who.browser).await;
	assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
	let response = who.assert(from, &begun);
	fx.stepup(
		"/auth/stepup/verify",
		from,
		json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
		&mut who.browser,
	)
	.await
}

#[tokio::test]
async fn a_passkey_from_a_listed_host_yields_a_proof_for_exactly_that_operation() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-passkey").await;
	for from in [SA, INVEST] {
		let begun = fx.begin(from, &HASH_A, &mut who.browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		assert_eq!(begun.body["options"]["publicKey"]["rpId"], "evinvest.test", "the relying party is the site, not the asking host");
		assert_eq!(begun.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], from);
		assert_eq!(begun.headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
		assert_eq!(begun.headers[header::CACHE_CONTROL], "no-store");

		let before = access_cookie_claims(&who.browser);
		let session = who.browser.get("ev_session").unwrap().to_owned();
		let response = who.assert(from, &begun);
		let done = fx
			.stepup(
				"/auth/stepup/verify",
				from,
				json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
				&mut who.browser,
			)
			.await;
		assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
		assert_eq!(done.body["method"], "passkey");

		let sub = who.user.to_string();
		let proof = done.body["proof"].as_str().unwrap();
		let claims = verify_stepup_proof(proof, &jwks(), ISSUER, &expect(&sub, from, &HASH_A)).expect("a proof for this operation");
		assert_eq!(
			(claims.method, claims.origin.as_str(), claims.aud.as_str(), claims.typ.as_str()),
			(StepupMethod::Passkey, from, "banking-bff", "stepup")
		);
		assert!(claims.exp - claims.iat <= 120);

		// Nothing else moved: same session, same access token, same `auth_time`.
		assert_eq!(who.browser.get("ev_session"), Some(session.as_str()));
		let after = access_cookie_claims(&who.browser);
		assert_eq!((&after["jti"], &after["auth_time"]), (&before["jti"], &before["auth_time"]));

		assert_eq!(
			verify_stepup_proof(proof, &jwks(), ISSUER, &expect(&sub, from, &HASH_B)).unwrap_err(),
			StepupError::Mismatch("operation"),
			"another operation's hash does not take it"
		);
		let other_page = if from == SA { INVEST } else { SA };
		assert_eq!(
			verify_stepup_proof(proof, &jwks(), ISSUER, &expect(&sub, other_page, &HASH_A)).unwrap_err(),
			StepupError::Mismatch("origin")
		);
		assert_eq!(
			verify_stepup_proof(proof, &jwks(), ISSUER, &expect("someone-else", from, &HASH_A)).unwrap_err(),
			StepupError::Mismatch("account")
		);
	}
}

#[tokio::test]
async fn a_proof_is_not_an_access_token() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-not-access").await;
	let done = prove(&fx, &mut who, SA, &HASH_A).await;
	let proof = done.body["proof"].as_str().unwrap();
	for audiences in [vec!["concierge".to_owned()], vec!["concierge".to_owned(), "banking-bff".to_owned()]] {
		let policy = VerifyPolicy {
			issuer: ISSUER.into(),
			audiences,
			allowed_types: vec![TokenType::Access, TokenType::Service],
		};
		assert!(verify_token(proof, &jwks(), &policy).is_err());
	}
	let access = who.browser.get("ev_access").unwrap();
	assert_eq!(
		verify_stepup_proof(access, &jwks(), ISSUER, &expect(&who.user.to_string(), SA, &HASH_A)).unwrap_err(),
		StepupError::Invalid,
		"nor the other way round"
	);
}

#[tokio::test]
async fn two_proofs_never_share_a_jti() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-jti").await;
	let sub = who.user.to_string();
	let mut seen = Vec::new();
	for _ in 0..2 {
		let done = prove(&fx, &mut who, SA, &HASH_A).await;
		let claims = verify_stepup_proof(done.body["proof"].as_str().unwrap(), &jwks(), ISSUER, &expect(&sub, SA, &HASH_A)).unwrap();
		assert!(!seen.contains(&claims.jti));
		seen.push(claims.jti);
	}
}

#[tokio::test]
async fn an_origin_that_is_not_listed_exactly_is_refused_and_cannot_read_the_answer() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-origin").await;
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
		let refused = fx.begin(rogue, &HASH_A, &mut who.browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })), "origin {rogue:?}");
		assert!(refused.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(), "origin {rogue:?} may not read the refusal");

		let answer = fx.wire_preflight(rogue, "/auth/stepup/options", &mut who.browser).await;
		assert!(answer.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(), "origin {rogue:?} gets no preflight approval");
	}
	// No Origin header at all.
	let mut none = Wire::post("/auth/stepup/options", SA, json!({ "intent_hash": hex(&HASH_A), "method": "passkey" }));
	none.origin = None;
	assert_eq!(fx.wire(none, &mut who.browser).await.status, StatusCode::FORBIDDEN);
}

impl Surface {
	async fn wire_preflight(&self, origin: &str, path: &str, browser: &mut Browser) -> Answer {
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
}

#[tokio::test]
async fn the_preflight_of_a_listed_origin_is_approved_for_a_minute() {
	let fx = fixture!();
	let mut browser = Browser::default();
	for from in [SA, INVEST] {
		for path in ["/auth/stepup/options", "/auth/stepup/verify"] {
			let answer = fx.wire_preflight(from, path, &mut browser).await;
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
	let mut who = enrolled(&fx, "stepup-meta").await;
	let body = json!({ "intent_hash": hex(&HASH_A), "method": "passkey" });
	for site in [None, Some("cross-site"), Some("none"), Some("")] {
		let mut wire = Wire::post("/auth/stepup/options", SA, body.clone());
		wire.site = site;
		let refused = fx.wire(wire, &mut who.browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::FORBIDDEN, json!({ "error": "fetch_site" })), "site {site:?}");
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
		let refused = fx.wire(wire, &mut who.browser).await;
		assert_eq!(
			(refused.status, refused.body),
			(StatusCode::UNSUPPORTED_MEDIA_TYPE, json!({ "error": "content_type" })),
			"content type {ct:?}"
		);
	}
}

#[tokio::test]
async fn without_the_flag_nothing_is_mounted() {
	let Some(fx) = surface().await else { return };
	let mut browser = Browser::default();
	fx.sign_in_with_code(&address("stepup-off"), &mut browser).await;
	for path in ["/auth/stepup/options", "/auth/stepup/verify"] {
		let answer = fx.stepup(path, SA, json!({}), &mut browser).await;
		assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
		let pre = fx.wire_preflight(SA, path, &mut browser).await;
		assert!(pre.headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
	}
}

#[tokio::test]
async fn a_ceremony_is_spent_once() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-replay").await;
	let begun = fx.begin(SA, &HASH_A, &mut who.browser).await;
	let response = who.assert(SA, &begun);
	let body = json!({ "ceremony_id": begun.body["ceremony_id"], "response": response });
	assert_eq!(fx.stepup("/auth/stepup/verify", SA, body.clone(), &mut who.browser).await.status, StatusCode::OK);
	let replay = fx.stepup("/auth/stepup/verify", SA, body, &mut who.browser).await;
	assert_eq!((replay.status, replay.body), (StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })));
}

#[tokio::test]
async fn a_ceremony_belongs_to_its_account_and_its_page() {
	let fx = fixture!();
	let mut owner = enrolled(&fx, "stepup-owner").await;
	let mut other = enrolled(&fx, "stepup-other").await;

	// Another account of another browser.
	let begun = fx.begin(SA, &HASH_A, &mut owner.browser).await;
	let stolen = owner.assert(SA, &begun);
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "response": stolen }),
			&mut other.browser,
		)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })));

	// Another listed page.
	let begun = fx.begin(SA, &HASH_A, &mut owner.browser).await;
	let response = owner.assert(INVEST, &begun);
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			INVEST,
			json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
			&mut owner.browser,
		)
		.await;
	assert_eq!(
		(refused.status, refused.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })),
		"begun on sa, finished from invest"
	);

	// The right page asking, an assertion made on another page.
	let begun = fx.begin(SA, &HASH_A, &mut owner.browser).await;
	let response = owner.assert(INVEST, &begun);
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
			&mut owner.browser,
		)
		.await;
	assert_eq!(
		(refused.status, refused.body),
		(StatusCode::UNAUTHORIZED, json!({ "error": "passkey_rejected" })),
		"the assertion names invest"
	);
}

#[tokio::test]
async fn a_lapsed_ceremony_gives_no_proof() {
	let fx = fixture!(1);
	let mut who = enrolled(&fx, "stepup-lapsed").await;
	let begun = fx.begin(SA, &HASH_A, &mut who.browser).await;
	let response = who.assert(SA, &begun);
	tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
			&mut who.browser,
		)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })));
}

#[tokio::test]
async fn a_key_made_after_the_session_began_is_neither_offered_nor_accepted() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-planted").await;
	let begun = fx.begin(SA, &HASH_A, &mut who.browser).await;
	assert_eq!(begun.status, StatusCode::OK);
	let response = who.assert(SA, &begun);
	sqlx::query("UPDATE passkey_credentials SET created_at = created_at + 200000 WHERE user_id = $1")
		.bind(who.user)
		.execute(&fx.pool)
		.await
		.unwrap();
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "response": response }),
			&mut who.browser,
		)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "passkey_rejected" })));
	let none = fx.begin(SA, &HASH_A, &mut who.browser).await;
	assert_eq!((none.status, none.body), (StatusCode::BAD_REQUEST, json!({ "error": "no_passkey" })), "it is not even offered");
}

#[tokio::test]
async fn a_password_is_not_a_way_in() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-password").await;
	let hash = hex(&HASH_A);
	let refused = fx
		.stepup("/auth/stepup/options", SA, json!({ "intent_hash": hash, "method": "password" }), &mut who.browser)
		.await;
	assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_method" })));
	let smuggled = fx
		.stepup(
			"/auth/stepup/options",
			SA,
			json!({ "intent_hash": hash, "method": "passkey", "password": "hunter2" }),
			&mut who.browser,
		)
		.await;
	assert_eq!(
		(smuggled.status, smuggled.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "invalid_request" })),
		"an unknown field is not ignored"
	);
	let garbage = fx
		.wire(
			Wire {
				body: Some("{not json".into()),
				..Wire::post("/auth/stepup/options", SA, json!({}))
			},
			&mut who.browser,
		)
		.await;
	assert_eq!(
		(garbage.status, garbage.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "invalid_request" })),
		"a parse error is in the surface's own shape"
	);
	let begun = fx.begin(SA, &HASH_A, &mut who.browser).await;
	let verify = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": begun.body["ceremony_id"], "password": "hunter2" }),
			&mut who.browser,
		)
		.await;
	assert_eq!((verify.status, verify.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_request" })));
	for path in ["/auth/stepup/password", "/auth/stepup/code/verify"] {
		let missing = fx.stepup(path, SA, json!({ "password": "x" }), &mut who.browser).await;
		assert!(matches!(missing.status, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED), "{path}: {:?}", missing.status);
	}
}

#[tokio::test]
async fn the_intent_hash_has_one_spelling() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-hash").await;
	for bad in [hex(&HASH_A).to_uppercase(), "aa".repeat(31), "aa".repeat(33), "zz".repeat(32), String::new()] {
		let refused = fx.stepup("/auth/stepup/options", SA, json!({ "intent_hash": bad, "method": "passkey" }), &mut who.browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_intent" })), "{bad:?}");
	}
}

#[tokio::test]
async fn it_needs_a_live_session() {
	let fx = fixture!();
	let mut anonymous = Browser::default();
	let refused = fx.begin(SA, &HASH_A, &mut anonymous).await;
	assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));

	let mut who = enrolled(&fx, "stepup-revoked").await;
	sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = $1")
		.bind(who.user)
		.execute(&fx.pool)
		.await
		.unwrap();
	let refused = fx.begin(SA, &HASH_A, &mut who.browser).await;
	assert_eq!((refused.status, refused.body), (StatusCode::UNAUTHORIZED, json!({ "error": "unauthenticated" })));
}

#[tokio::test]
async fn asking_is_budgeted_per_account() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-budget").await;
	let mut last = StatusCode::OK;
	for _ in 0..11 {
		last = fx.begin(SA, &HASH_A, &mut who.browser).await.status;
	}
	assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
	let mut stranger = enrolled(&fx, "stepup-budget-other").await;
	assert_eq!(fx.begin(SA, &HASH_A, &mut stranger.browser).await.status, StatusCode::OK, "another account has its own");
}

#[tokio::test]
async fn an_account_holds_at_most_three_ceremonies_and_evicts_its_own_oldest() {
	let fx = fixture!();
	let mut who = enrolled(&fx, "stepup-cap").await;
	let mut other = enrolled(&fx, "stepup-cap-other").await;
	let theirs = fx.begin(SA, &HASH_B, &mut other.browser).await;
	let mut ceremonies = Vec::new();
	for _ in 0..4 {
		let begun = fx.begin(SA, &HASH_A, &mut who.browser).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		ceremonies.push(begun);
	}
	// Assertions are made up front; they need the options of their own ceremony.
	let oldest = who.assert(SA, &ceremonies[0]);
	let refused = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": ceremonies[0].body["ceremony_id"], "response": oldest }),
			&mut who.browser,
		)
		.await;
	assert_eq!(
		(refused.status, refused.body),
		(StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })),
		"the fourth evicted the first"
	);
	let newest = who.assert(SA, &ceremonies[3]);
	let done = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": ceremonies[3].body["ceremony_id"], "response": newest }),
			&mut who.browser,
		)
		.await;
	assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
	let theirs_response = other.assert(SA, &theirs);
	let theirs_done = fx
		.stepup(
			"/auth/stepup/verify",
			SA,
			json!({ "ceremony_id": theirs.body["ceremony_id"], "response": theirs_response }),
			&mut other.browser,
		)
		.await;
	assert_eq!(theirs_done.status, StatusCode::OK, "another account's ceremony was not evicted");
}

mod email {
	use super::*;

	async fn mail(fx: &Surface, email: &str) -> Value {
		sqlx::query_scalar("SELECT payload FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1 AND payload->>'purpose' = 'stepup' ORDER BY id DESC LIMIT 1")
			.bind(email)
			.fetch_one(&fx.pool)
			.await
			.expect("a step-up code was queued")
	}

	async fn ask(fx: &Surface, who: &mut Enrolled, from: &str, hash: &[u8; 32], summary: Option<&str>) -> Answer {
		let mut body = json!({ "intent_hash": hex(hash), "method": "email_code", "turnstile_token": "human" });
		if let Some(summary) = summary {
			body["summary"] = json!(summary);
		}
		fx.stepup("/auth/stepup/options", from, body, &mut who.browser).await
	}

	#[tokio::test]
	async fn a_mailed_code_yields_a_proof_and_the_mail_names_the_operation() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-code").await;
		let begun = ask(&fx, &mut who, INVEST, &HASH_A, Some("Send 5 USDT to TXyz")).await;
		assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
		assert_eq!(begun.body["method"], "email_code");

		let payload = mail(&fx, &who.email).await;
		assert_eq!(
			(payload["origin"].as_str(), payload["summary"].as_str(), payload["reference"].as_str()),
			(Some(INVEST), Some("Send 5 USDT to TXyz"), Some(&hex(&HASH_A)[..8]))
		);
		assert!(payload["requested_at"].as_i64().is_some() && payload["client_ip"].is_string());
		let code = payload["code"].as_str().unwrap().to_owned();
		assert!(
			payload["expires_at"].as_i64().unwrap() - payload["requested_at"].as_i64().unwrap() <= 120,
			"the code lives as long as the ceremony"
		);

		let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
		let id = &begun.body["ceremony_id"];
		let refused = fx.stepup("/auth/stepup/verify", INVEST, json!({ "ceremony_id": id, "code": wrong }), &mut who.browser).await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })));

		let done = fx.stepup("/auth/stepup/verify", INVEST, json!({ "ceremony_id": id, "code": code }), &mut who.browser).await;
		assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
		let claims = verify_stepup_proof(done.body["proof"].as_str().unwrap(), &jwks(), ISSUER, &expect(&who.user.to_string(), INVEST, &HASH_A)).unwrap();
		assert_eq!(claims.method, StepupMethod::EmailCode);

		let replay = fx.stepup("/auth/stepup/verify", INVEST, json!({ "ceremony_id": id, "code": code }), &mut who.browser).await;
		assert_eq!(
			(replay.status, replay.body),
			(StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })),
			"the same code, the same ceremony: once"
		);
	}

	#[tokio::test]
	async fn a_code_is_for_the_latest_operation_only() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-latest").await;
		let first = ask(&fx, &mut who, SA, &HASH_A, Some("Operation A")).await;
		let second = ask(&fx, &mut who, SA, &HASH_B, Some("Operation B")).await;
		assert_eq!((first.status, second.status), (StatusCode::OK, StatusCode::OK));
		let code = mail(&fx, &who.email).await["code"].as_str().unwrap().to_owned();

		let stale = fx
			.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": first.body["ceremony_id"], "code": code }), &mut who.browser)
			.await;
		assert_eq!(
			(stale.status, stale.body),
			(StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })),
			"B's code cannot close A's ceremony"
		);
		let done = fx
			.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": second.body["ceremony_id"], "code": code }), &mut who.browser)
			.await;
		assert_eq!(done.status, StatusCode::OK);
		let sub = who.user.to_string();
		assert!(verify_stepup_proof(done.body["proof"].as_str().unwrap(), &jwks(), ISSUER, &expect(&sub, SA, &HASH_B)).is_ok());
	}

	#[tokio::test]
	async fn the_other_codes_of_the_account_do_not_stand_in() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-purpose").await;
		let asked = fx.post("/auth/reauth/code/request", ORIGIN, json!({ "turnstileToken": "human" }), &mut who.browser).await;
		assert_eq!(asked.body, json!({ "ok": true }));
		let reauth = fx.mailed_code(&who.email, "reauth").await;
		let begun = ask(&fx, &mut who, SA, &HASH_A, Some("Operation A")).await;
		let refused = fx
			.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": begun.body["ceremony_id"], "code": reauth }), &mut who.browser)
			.await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_code" })));
	}

	#[tokio::test]
	async fn the_summary_is_required_short_and_one_line_and_a_person_must_ask() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-summary").await;
		for bad in [None, Some(""), Some("two\nlines"), Some("\u{202e}reversed"), Some(&"x".repeat(241))] {
			let refused = ask(&fx, &mut who, SA, &HASH_A, bad).await;
			assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "invalid_summary" })), "{bad:?}");
		}
		let robot = fx
			.stepup(
				"/auth/stepup/options",
				SA,
				json!({ "intent_hash": hex(&HASH_A), "method": "email_code", "summary": "ok", "turnstile_token": "bot" }),
				&mut who.browser,
			)
			.await;
		assert_eq!((robot.status, robot.body), (StatusCode::FORBIDDEN, json!({ "error": "captcha" })));
	}

	#[tokio::test]
	async fn a_lapsed_code_ceremony_gives_no_proof() {
		let fx = fixture!(1);
		let mut who = enrolled(&fx, "stepup-code-lapsed").await;
		let begun = ask(&fx, &mut who, SA, &HASH_A, Some("Operation A")).await;
		let code = mail(&fx, &who.email).await["code"].as_str().unwrap().to_owned();
		tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
		let refused = fx
			.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": begun.body["ceremony_id"], "code": code }), &mut who.browser)
			.await;
		assert_eq!((refused.status, refused.body), (StatusCode::BAD_REQUEST, json!({ "error": "passkey_expired" })));
	}

	#[tokio::test]
	async fn five_wrong_guesses_burn_the_code() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-burn").await;
		let begun = ask(&fx, &mut who, SA, &HASH_A, Some("Operation A")).await;
		let code = mail(&fx, &who.email).await["code"].as_str().unwrap().to_owned();
		let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
		let mut last = Value::Null;
		for _ in 0..5 {
			last = fx
				.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": begun.body["ceremony_id"], "code": wrong }), &mut who.browser)
				.await
				.body;
		}
		assert_eq!(last, json!({ "error": "attempts_exceeded" }));
		let right = fx
			.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": begun.body["ceremony_id"], "code": code }), &mut who.browser)
			.await;
		assert!(!right.status.is_success(), "a burned code is dead even when right");
	}

	#[tokio::test]
	async fn a_code_mailed_for_one_operation_never_closes_the_ceremony_of_another() {
		let fx = fixture!();
		let mut who = enrolled(&fx, "stepup-race").await;
		let sub = who.user.to_string();
		// Two rounds: each spends four of the account's ten asks.
		for round in 0..2 {
			let (a, b) = {
				let mut second = who.browser.clone();
				tokio::join!(ask(&fx, &mut who, SA, &HASH_A, Some("Operation A")), async {
					fx.stepup(
						"/auth/stepup/options",
						SA,
						json!({ "intent_hash": hex(&HASH_B), "method": "email_code", "turnstile_token": "human", "summary": "Operation B" }),
						&mut second,
					)
					.await
				})
			};
			assert_eq!((a.status, b.status), (StatusCode::OK, StatusCode::OK), "round {round}: {:?} {:?}", a.body, b.body);
			// The code that is live is bound to whichever operation was issued last.
			let bound: Vec<u8> =
				sqlx::query_scalar("SELECT binding FROM email_codes WHERE user_id = $1 AND purpose = 'stepup' AND burned_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 1")
					.bind(who.user)
					.fetch_one(&fx.pool)
					.await
					.unwrap();
			let code = mail(&fx, &who.email).await["code"].as_str().unwrap().to_owned();
			for (ceremony, hash) in [(&a, &HASH_A), (&b, &HASH_B)] {
				let answer = fx
					.stepup("/auth/stepup/verify", SA, json!({ "ceremony_id": ceremony.body["ceremony_id"], "code": code }), &mut who.browser)
					.await;
				if answer.status == StatusCode::OK {
					assert_eq!(bound, hash.to_vec(), "round {round}: a proof for an operation the code was not mailed for");
					assert!(verify_stepup_proof(answer.body["proof"].as_str().unwrap(), &jwks(), ISSUER, &expect(&sub, SA, hash)).is_ok());
				} else {
					assert_ne!(bound, hash.to_vec(), "round {round}: the right ceremony was refused");
				}
			}
		}
	}
}
