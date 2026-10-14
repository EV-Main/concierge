//! The scope registry (migration 0031) and what it opens on the web surface: the
//! `ScopeRegistry` read service, CORS and the `Origin` check on the closed list of sign-in
//! routes, and the micro-frontend bundles under `/auth/mfe/*`.

mod common;

use std::{path::PathBuf, sync::Arc};

use axum::{
	Router,
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header},
};
use concierge::{
	infrastructure::{db, governance::PgGovernance, kyc::cases::PgKycCases, notifications::PgNotifications, scopes::PgScopes, users::PgUsers},
	ports::{ScopeRecord, ScopeRepository},
	scopes::ScopeRegistry,
	web::{
		self, KycDeps,
		allowlist::SignInAllowlist,
		mfe::{self, MfeAssets},
		origins::ScopeOrigins,
	},
};
use domain::scopes::ScopeState;
use evconcierge_auth::{Claims, TokenType};
use evconcierge_contracts::concierge::v1::{self as cc, GetScopeRequest, ListScopesRequest, scope_registry_server::ScopeRegistry as _};
use serde_json::{Value, json};
use sqlx::PgPool;
use tonic::{Code, Request as RpcRequest};
use tower::ServiceExt;
use uuid::Uuid;

const PUBLIC: &str = "https://evinvest.test";
const INVEST: &str = "https://invest.evinvest.ltd";

async fn pool() -> Option<PgPool> {
	let url = common::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	Some(pool)
}

macro_rules! pool {
	() => {
		match pool().await {
			Some(pool) => pool,
			None => return,
		}
	};
}

fn tag() -> String {
	format!("t{}", &Uuid::new_v4().simple().to_string()[..12])
}

async fn version_of(pool: &PgPool, id: &str) -> i64 {
	sqlx::query_scalar("SELECT version FROM tenants WHERE id = $1").bind(id).fetch_one(pool).await.unwrap()
}

// ── the registry ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_migration_seeds_invest_and_gives_sa_its_host() {
	let pool = pool!();
	let scopes = PgScopes::new(pool.clone()).scopes().await.expect("read the registry");

	let invest = scopes.iter().find(|s| s.id == "invest").expect("invest is seeded");
	assert_eq!((invest.namespace.as_str(), invest.parent.as_str(), invest.state), ("invest", "main", ScopeState::Active));
	assert_eq!(invest.origins, vec![INVEST]);
	assert_eq!(invest.return_paths, vec!["/cabinet", "/"], "0031 seeded /cabinet, 0035 appended /");
	assert_eq!(invest.clients.len(), 1);
	assert_eq!(
		(invest.clients[0].client_id.as_str(), invest.clients[0].audience.as_str(), invest.clients[0].disabled),
		("invest", "invest", false)
	);

	let sa = scopes.iter().find(|s| s.id == "sa").expect("sa is seeded");
	assert_eq!(sa.origins, vec!["https://sa.evinvest.ltd"]);
	assert_eq!(sa.return_paths, vec!["/", "/auth/login"]);
	assert_eq!(sa.observers, vec!["invest"]);
	assert_eq!(sa.clients.iter().map(|c| c.client_id.as_str()).collect::<Vec<_>>(), vec!["sa"]);

	// The secret is not asserted: it is env, written by whichever suite syncs the registry.
	let redirects: Vec<String> = sqlx::query_scalar("SELECT redirect_uris FROM rp_clients WHERE client_id = 'invest'")
		.fetch_one(&pool)
		.await
		.unwrap();
	assert_eq!(redirects, vec!["https://invest.evinvest.ltd/cabinet/auth/callback"]);
	let hold_all: bool = sqlx::query_scalar("SELECT granting_seats_hold_all FROM tenants WHERE id = 'invest'")
		.fetch_one(&pool)
		.await
		.unwrap();
	assert!(hold_all);
}

#[tokio::test]
async fn a_scope_moves_its_version_on_any_change_but_a_secret_rotation() {
	let pool = pool!();
	let id = tag();
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, FALSE, 0)")
		.bind(&id)
		.execute(&pool)
		.await
		.unwrap();
	assert_eq!(version_of(&pool, &id).await, 1);

	sqlx::query("UPDATE tenants SET display_name = 'Renamed' WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
	assert_eq!(version_of(&pool, &id).await, 2);
	sqlx::query("UPDATE tenants SET display_name = 'Renamed' WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
	assert_eq!(version_of(&pool, &id).await, 2, "a write that changes nothing is no new version");

	sqlx::query("INSERT INTO rp_clients (client_id, audience, redirect_uris, tenant_id, created_at) VALUES ($1, $1, ARRAY['https://x.evinvest.ltd/cb'], $1, 0)")
		.bind(&id)
		.execute(&pool)
		.await
		.unwrap();
	assert_eq!(version_of(&pool, &id).await, 3, "a new client is part of the scope");

	sqlx::query("UPDATE rp_clients SET secret_hash = $2, secret_set_at = 1 WHERE client_id = $1")
		.bind(&id)
		.bind(vec![7u8; 32])
		.execute(&pool)
		.await
		.unwrap();
	assert_eq!(version_of(&pool, &id).await, 3, "a client's secret is not in the scope message");

	sqlx::query("UPDATE rp_clients SET disabled_at = 1 WHERE client_id = $1").bind(&id).execute(&pool).await.unwrap();
	assert_eq!(version_of(&pool, &id).await, 4, "disabling a client is");
}

#[tokio::test]
async fn the_registry_refuses_what_could_widen_sign_in() {
	let pool = pool!();
	let id = tag();
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ($1, $1, FALSE, 0)")
		.bind(&id)
		.execute(&pool)
		.await
		.unwrap();
	for origin in [
		"http://x.evinvest.ltd",
		"https://x.evinvest.ltd/",
		"https://*.evinvest.ltd",
		"https://xevinvest.ltd",
		"https://evinvest.ltd.evil.example",
		"https://x.evinvest.ltd:443",
		"https://x.evinvest.ltd:0",
		"https://x.evinvest.ltd:65536",
		"https://x.evinvest.ltd:99999",
		"https://evinvest.ltd",
		"https://evinvest.ltd:8443",
		"null",
	] {
		let refused = sqlx::query("UPDATE tenants SET origins = ARRAY[$2] WHERE id = $1").bind(&id).bind(origin).execute(&pool).await;
		assert!(refused.is_err(), "{origin}");
	}
	for path in ["//evil.example", "/cabinet/", "/cabinet?x=1", "cabinet"] {
		let refused = sqlx::query("UPDATE tenants SET return_paths = ARRAY[$2] WHERE id = $1").bind(&id).bind(path).execute(&pool).await;
		assert!(refused.is_err(), "{path}");
	}
	// `bool_and` skips NULLs; the CHECKs must not, or the row would fail to decode later.
	for column in ["origins", "return_paths", "observers"] {
		let null = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE tenants SET {column} = ARRAY[NULL]::TEXT[] WHERE id = $1")))
			.bind(&id)
			.execute(&pool)
			.await;
		assert!(null.is_err(), "a NULL element in {column}");
	}
	let accepted = sqlx::query("UPDATE tenants SET origins = ARRAY['https://x.evinvest.ltd:65535'] WHERE id = $1")
		.bind(&id)
		.execute(&pool)
		.await;
	assert!(accepted.is_ok(), "the highest port is a port");
	let main = sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at) VALUES ('main', $1, FALSE, 0)")
		.bind(tag())
		.execute(&pool)
		.await;
	assert!(main.is_err(), "`main` is the implicit root and never a row");
}

fn signed_in<T>(inner: T) -> RpcRequest<T> {
	let mut request = RpcRequest::new(inner);
	request.extensions_mut().insert(Claims {
		sub: Uuid::new_v4().to_string(),
		iss: "https://auth.concierge.test".into(),
		aud: "concierge".into(),
		exp: u64::MAX,
		iat: 0,
		typ: TokenType::Access,
		jti: None,
		token_version: 0,
	});
	request
}

#[tokio::test]
async fn scope_registry_lists_main_first_and_reads_one_scope() {
	let pool = pool!();
	let registry = ScopeRegistry::new(Arc::new(PgScopes::new(pool)));

	let scopes = registry.list_scopes(signed_in(ListScopesRequest {})).await.expect("list").into_inner().scopes;
	assert_eq!(scopes[0].id, "main");
	assert_eq!((scopes[0].namespace.as_str(), scopes[0].parent.as_str()), ("", ""));
	assert!(scopes[0].origins.is_empty() && scopes[0].clients.is_empty());
	let ids: Vec<&str> = scopes[1..].iter().map(|s| s.id.as_str()).collect();
	assert!(ids.is_sorted(), "{ids:?}");
	assert!(ids.contains(&"invest") && ids.contains(&"sa"));

	let invest = registry.get_scope(signed_in(GetScopeRequest { scope: "invest".into() })).await.expect("get").into_inner();
	assert_eq!(invest.parent, "main");
	assert_eq!(invest.state, cc::ScopeState::Active as i32);
	assert_eq!(invest.origins, vec![INVEST]);
	assert_eq!(invest.return_paths, vec!["/cabinet", "/"], "0031 seeded /cabinet, 0035 appended /");
	assert!(invest.version >= 1);
	assert_eq!(
		invest.clients,
		vec![cc::ScopeClient {
			client_id: "invest".into(),
			audience: "invest".into(),
			disabled: false
		}]
	);

	let main = registry.get_scope(signed_in(GetScopeRequest { scope: "main".into() })).await.expect("main").into_inner();
	assert_eq!(main.id, "main");

	let missing = registry.get_scope(signed_in(GetScopeRequest { scope: "nope".into() })).await.unwrap_err();
	assert_eq!(missing.code(), Code::NotFound);

	let anonymous = registry.list_scopes(RpcRequest::new(ListScopesRequest {})).await.unwrap_err();
	assert_eq!(anonymous.code(), Code::Unauthenticated, "a claims-less request reads nothing");
}

// ── sign-in from a scope's host ────────────────────────────────────────────────────

/// The web surface over the live registry, plus a CLOSED scope whose host must be
/// treated like any stranger's.
async fn sign_in_surface(pool: &PgPool) -> (Router, String, Arc<SignInAllowlist>) {
	let closed = tag();
	let closed_origin = format!("https://{closed}.evinvest.ltd");
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, origins, return_paths, state) VALUES ($1, $1, FALSE, 0, ARRAY[$2], ARRAY['/'], 'closed')")
		.bind(&closed)
		.bind(&closed_origin)
		.execute(pool)
		.await
		.unwrap();
	let users = Arc::new(PgUsers::new(pool.clone()));
	let mut sign_in = common::sign_in_with_turnstile(pool, &common::stub_turnstile().await);
	// Refreshed by the test itself (`refresh`), standing in for the background loop.
	let allowlist = Arc::new(SignInAllowlist::live(Arc::new(PgScopes::new(pool.clone())), PUBLIC).await.unwrap());
	sign_in.allowlist = allowlist.clone();
	let state = web::WebState::try_new(
		common::signing_auth(users.clone()).await,
		PUBLIC.to_string(),
		false,
		sign_in,
		KycDeps {
			users,
			cases: Arc::new(PgKycCases::new(pool.clone())),
			notifications: Arc::new(PgNotifications::new(pool.clone())),
			governance: Arc::new(PgGovernance::new(pool.clone(), format!("{PUBLIC}/governance"))),
			provider: None,
			support_email: "support@evinvest.test".into(),
			case_ttl_secs: 86_400,
		},
		None,
	)
	.await
	.expect("build the web state");
	(web::router(state), closed_origin, allowlist)
}

async fn preflight(router: &Router, path: &str, origin: &str, method: &str) -> (StatusCode, HeaderMap) {
	let response = router
		.clone()
		.oneshot(
			Request::builder()
				.method(Method::OPTIONS)
				.uri(path)
				.header(header::ORIGIN, origin)
				.header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
				.header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	(response.status(), response.headers().clone())
}

async fn call(router: &Router, method: Method, path: &str, origin: &str, body: Option<Value>) -> (StatusCode, HeaderMap, Value) {
	let mut request = Request::builder().method(method).uri(path).header(header::ORIGIN, origin);
	if body.is_some() {
		request = request.header(header::CONTENT_TYPE, "application/json");
	}
	let response = router
		.clone()
		.oneshot(request.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string()))).unwrap())
		.await
		.unwrap();
	let (status, headers) = (response.status(), response.headers().clone());
	let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
	(status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn varies_on_origin(headers: &HeaderMap) -> bool {
	headers
		.get_all(header::VARY)
		.iter()
		.any(|v| v.to_str().unwrap().split(',').any(|p| p.trim().eq_ignore_ascii_case("origin")))
}

#[tokio::test]
async fn a_scope_host_passes_the_preflight_of_a_sign_in_route() {
	let pool = pool!();
	let (router, _, _) = sign_in_surface(&pool).await;

	let (status, headers) = preflight(&router, "/auth/code/request", INVEST, "POST").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST, "exactly the origin, never `*`");
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_METHODS], "POST");
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_HEADERS], "content-type");
	assert_eq!(headers[header::ACCESS_CONTROL_MAX_AGE], "600");
	assert!(varies_on_origin(&headers));

	let (status, headers) = preflight(&router, "/auth/session", "https://sa.evinvest.ltd", "GET").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_METHODS], "GET");
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://sa.evinvest.ltd");
}

#[tokio::test]
async fn nothing_but_a_registered_live_origin_passes_the_preflight() {
	let pool = pool!();
	let (router, closed_origin, _) = sign_in_surface(&pool).await;
	for origin in [
		"https://evil.example",
		"null",
		"http://invest.evinvest.ltd",
		"https://invest.evinvest.ltd.evil.example",
		"https://evil.example.invest.evinvest.ltd",
		"https://invest.evinvest.ltd:8443",
		"https://invest.evinvest.ltd/",
		"https://INVEST.evinvest.ltd",
		closed_origin.as_str(),
	] {
		let (_, headers) = preflight(&router, "/auth/code/request", origin, "POST").await;
		// The verdict is `Access-Control-Allow-Origin` alone: tower-http's layer sends the
		// static `Allow-Credentials` on every answer, and without the origin a browser
		// lets the page read nothing.
		assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{origin}");
	}
	// A registered origin asking for a method the route does not take is offered only the
	// one it does, which a browser then refuses to send.
	let (_, headers) = preflight(&router, "/auth/session", INVEST, "DELETE").await;
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_METHODS], "GET");
}

#[tokio::test]
async fn a_route_acting_on_an_open_session_answers_no_scope_host() {
	let pool = pool!();
	let (router, _, _) = sign_in_surface(&pool).await;
	for path in [
		"/auth/email/verify/request",
		"/auth/email/verify/confirm",
		"/auth/password/set",
		"/auth/passkey/register/options",
		"/auth/passkey/remove",
		"/auth/sessions",
		"/auth/username",
		"/auth/logout",
		"/auth/logout/confirm",
		"/kyc/start",
	] {
		let (_, headers) = preflight(&router, path, INVEST, "POST").await;
		assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "preflight {path}");
		let (_, headers, _) = call(&router, Method::POST, path, INVEST, Some(json!({}))).await;
		assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{path}");
	}
}

#[tokio::test]
async fn a_scope_host_requests_a_code_and_reads_the_answer() {
	let pool = pool!();
	let (router, _, _) = sign_in_surface(&pool).await;
	let email = format!("scope-{}@example.com", Uuid::new_v4().simple());
	let (status, headers, body) = call(&router, Method::POST, "/auth/code/request", INVEST, Some(json!({ "email": email, "turnstileToken": "human" }))).await;
	assert_eq!((status, body), (StatusCode::OK, json!({ "ok": true })));
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
	assert!(varies_on_origin(&headers));
}

/// The `Origin` check on the credential POSTs is the login-CSRF guard, and it widens to
/// registered live scope hosts and nothing else.
#[tokio::test]
async fn a_credential_post_from_any_other_origin_is_refused() {
	let pool = pool!();
	let (router, closed_origin, _) = sign_in_surface(&pool).await;
	let body = json!({ "email": "x@example.com", "turnstileToken": "human" });
	for origin in [
		"https://evil.example",
		"null",
		"http://invest.evinvest.ltd",
		"https://invest.evinvest.ltd.evil.example",
		closed_origin.as_str(),
	] {
		let (status, headers, answer) = call(&router, Method::POST, "/auth/code/request", origin, Some(body.clone())).await;
		assert_eq!((status, answer), (StatusCode::FORBIDDEN, json!({ "error": "origin" })), "{origin}");
		assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{origin}");
		assert!(varies_on_origin(&headers), "{origin}");
	}
	let (status, _, answer) = call(&router, Method::POST, "/auth/passkey/signin/options", "https://evil.example", Some(json!({}))).await;
	assert_eq!((status, answer), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));
	let (status, headers, _) = call(&router, Method::POST, "/auth/passkey/signin/options", INVEST, Some(json!({}))).await;
	assert_eq!(status, StatusCode::OK, "a scope host may begin a passkey sign-in");
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
}

#[tokio::test]
async fn the_session_read_from_a_scope_host_carries_no_token() {
	let pool = pool!();
	let (router, _, _) = sign_in_surface(&pool).await;
	let (status, headers, body) = call(&router, Method::GET, "/auth/session", INVEST, None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	assert_eq!(body["authenticated"], false);
	let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
	assert!(keys.iter().all(|k| ["authenticated", "user", "permissions"].contains(k)), "{keys:?}");
}

// ── the micro-frontend bundles ─────────────────────────────────────────────────────

struct Bundles {
	dir: PathBuf,
	outside: PathBuf,
}

impl Drop for Bundles {
	fn drop(&mut self) {
		// Best effort: a leftover temp dir fails nothing.
		let _ = std::fs::remove_dir_all(&self.dir);
		let _ = std::fs::remove_dir_all(&self.outside);
	}
}

fn bundles() -> (Router, Bundles) {
	let base = std::env::temp_dir().join(format!("concierge-mfe-{}", Uuid::new_v4().simple()));
	let dir = base.join("dist");
	let outside = std::env::temp_dir().join(format!("concierge-mfe-outside-{}", Uuid::new_v4().simple()));
	std::fs::create_dir_all(dir.join("chunks")).unwrap();
	std::fs::create_dir_all(&outside).unwrap();
	std::fs::write(dir.join("registry.json"), r#"{"sign-in":"sign-in-ABCD2345.js"}"#).unwrap();
	std::fs::write(dir.join("sign-in-ABCD2345.js"), "export {};").unwrap();
	std::fs::write(dir.join("chunks").join("chunk-Q7ZK3M2P.js"), "export {};").unwrap();
	std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
	std::fs::write(dir.join("LICENSES.txt"), "MIT").unwrap();
	std::fs::write(outside.join("secret.txt"), "outside").unwrap();
	std::os::unix::fs::symlink(outside.join("secret.txt"), dir.join("escape.txt")).unwrap();

	let origins = ScopeOrigins::from_scopes(&[ScopeRecord {
		id: "invest".into(),
		namespace: "invest".into(),
		parent: "main".into(),
		display_name: String::new(),
		origins: vec![INVEST.into()],
		return_paths: vec!["/cabinet".into()],
		observers: Vec::new(),
		clients: Vec::new(),
		created_at: 0,
		version: 1,
		state: ScopeState::Active,
	}]);
	let allowlist = Arc::new(SignInAllowlist::fixed(PUBLIC, origins).unwrap());
	let router = mfe::mount(Router::new(), MfeAssets::open(&dir, allowlist).expect("open the bundle directory"));
	(router, Bundles { dir: base, outside })
}

async fn fetch(router: &Router, method: Method, path: &str, origin: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
	let mut request = Request::builder().method(method).uri(path);
	if let Some(origin) = origin {
		request = request.header(header::ORIGIN, origin);
	}
	let response = router.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
	let (status, headers) = (response.status(), response.headers().clone());
	(status, headers, axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec())
}

#[tokio::test]
async fn the_manifest_is_short_lived_and_hashed_bundles_are_immutable() {
	let (router, _bundles) = bundles();

	let (status, headers, body) = fetch(&router, Method::GET, "/auth/mfe/registry.json", None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::CONTENT_TYPE], "application/json");
	assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300");
	assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
	assert_eq!(body, br#"{"sign-in":"sign-in-ABCD2345.js"}"#);

	let (status, headers, _) = fetch(&router, Method::GET, "/auth/mfe/chunks/chunk-Q7ZK3M2P.js", None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
	assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=31536000, immutable");

	let (status, headers, body) = fetch(&router, Method::HEAD, "/auth/mfe/sign-in-ABCD2345.js", None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
	assert!(body.is_empty(), "HEAD carries no body");

	let (_, headers, _) = fetch(&router, Method::GET, "/auth/mfe/LICENSES.txt", None).await;
	assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300", "an all-caps name is no content hash");
}

async fn fetch_with(router: &Router, path: &str, name: header::HeaderName, value: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
	let response = router.clone().oneshot(Request::get(path).header(name, value).body(Body::empty()).unwrap()).await.unwrap();
	let (status, headers) = (response.status(), response.headers().clone());
	(status, headers, axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec())
}

#[tokio::test]
async fn the_bundles_revalidate_and_serve_ranges() {
	let (router, _bundles) = bundles();
	let (_, headers, _) = fetch(&router, Method::GET, "/auth/mfe/registry.json", None).await;
	let etag = headers[header::ETAG].to_str().unwrap().to_owned();
	assert!(headers.contains_key(header::LAST_MODIFIED));

	let (status, headers, body) = fetch_with(&router, "/auth/mfe/registry.json", header::IF_NONE_MATCH, &etag).await;
	assert_eq!(status, StatusCode::NOT_MODIFIED);
	assert!(body.is_empty());
	assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300", "a 304 renews the same lifetime");

	let (status, headers, body) = fetch_with(&router, "/auth/mfe/sign-in-ABCD2345.js", header::RANGE, "bytes=0-5").await;
	assert_eq!(status, StatusCode::PARTIAL_CONTENT);
	assert_eq!(body, b"export");
	assert_eq!(headers[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
}

#[tokio::test]
async fn the_bundles_answer_a_scope_host_without_credentials() {
	let (router, _bundles) = bundles();
	let (_, headers, _) = fetch(&router, Method::GET, "/auth/mfe/registry.json", Some(INVEST)).await;
	assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], INVEST);
	assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
	assert!(varies_on_origin(&headers));

	let (_, headers, _) = fetch(&router, Method::GET, "/auth/mfe/registry.json", Some("https://evil.example")).await;
	assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn nothing_outside_the_files_is_served() {
	let (router, _bundles) = bundles();
	for path in [
		"/auth/mfe/",
		"/auth/mfe/chunks",
		"/auth/mfe/chunks/",
		"/auth/mfe/../secret.txt",
		"/auth/mfe/chunks/../registry.json",
		"/auth/mfe/%2e%2e/secret.txt",
		"/auth/mfe/chunks/%2e%2e/%2e%2e/secret.txt",
		"/auth/mfe/..%2fsecret.txt",
		"/auth/mfe/.env",
		"/auth/mfe/escape.txt",
		"/auth/mfe/missing.js",
		"/auth/mfe/a%5c..%5csecret.txt",
	] {
		let (status, _, body) = fetch(&router, Method::GET, path, None).await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
		assert!(!String::from_utf8_lossy(&body).contains("outside"), "{path}");
	}
	for method in [Method::POST, Method::PUT, Method::DELETE] {
		let (status, _, _) = fetch(&router, method.clone(), "/auth/mfe/registry.json", None).await;
		assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
	}
}

#[tokio::test]
async fn a_missing_bundle_directory_is_not_mounted() {
	let missing = std::env::temp_dir().join(format!("concierge-mfe-missing-{}", Uuid::new_v4().simple()));
	let none = || Arc::new(SignInAllowlist::fixed(PUBLIC, ScopeOrigins::none()).unwrap());
	assert!(MfeAssets::open(&missing, none()).is_err());
	let file = std::env::temp_dir().join(format!("concierge-mfe-file-{}", Uuid::new_v4().simple()));
	std::fs::write(&file, "not a directory").unwrap();
	assert!(MfeAssets::open(&file, none()).is_err());
	// Best effort: a leftover temp file fails nothing.
	let _ = std::fs::remove_file(&file);
}

// ── a live registry ────────────────────────────────────────────────────────────────

/// Closing a scope, or dropping an origin from it, stops it being let in by the next
/// reading of the registry — no restart.
#[tokio::test]
async fn a_closed_scope_or_a_removed_origin_stops_signing_in_without_a_restart() {
	let pool = pool!();
	let (router, _, allowlist) = sign_in_surface(&pool).await;
	let id = tag();
	let origin = format!("https://{id}.evinvest.ltd");
	let admitted = |headers: &HeaderMap| headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN);
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, origins, return_paths) VALUES ($1, $1, FALSE, 0, ARRAY[$2], ARRAY['/'])")
		.bind(&id)
		.bind(&origin)
		.execute(&pool)
		.await
		.unwrap();
	assert!(
		!admitted(&preflight(&router, "/auth/code/request", &origin, "POST").await.1),
		"nothing waits on the database: the snapshot in hand answers"
	);
	assert!(allowlist.refresh().await, "a new scope is a new snapshot");
	assert!(
		admitted(&preflight(&router, "/auth/code/request", &origin, "POST").await.1),
		"registered after the router was built"
	);
	assert!(!allowlist.refresh().await, "nothing changed, nothing is rebuilt");

	sqlx::query("UPDATE tenants SET state = 'frozen' WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
	allowlist.refresh().await;
	assert!(admitted(&preflight(&router, "/auth/code/request", &origin, "POST").await.1), "a frozen scope still signs in");

	sqlx::query("UPDATE tenants SET state = 'closed' WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
	assert!(allowlist.refresh().await);
	assert!(!admitted(&preflight(&router, "/auth/code/request", &origin, "POST").await.1), "closed");
	let (status, _, body) = call(
		&router,
		Method::POST,
		"/auth/code/request",
		&origin,
		Some(json!({ "email": "x@example.com", "turnstileToken": "human" })),
	)
	.await;
	assert_eq!((status, body), (StatusCode::FORBIDDEN, json!({ "error": "origin" })));

	sqlx::query("UPDATE tenants SET state = 'active', origins = '{}' WHERE id = $1")
		.bind(&id)
		.execute(&pool)
		.await
		.unwrap();
	allowlist.refresh().await;
	assert!(!admitted(&preflight(&router, "/auth/code/request", &origin, "POST").await.1), "removed");
}

/// A row that does not decode costs its own scope, never the plane's start. The CHECKs
/// make such a row unwritable, so this one is planted with them dropped — in a database
/// of its own.
#[tokio::test]
async fn a_malformed_registry_row_is_left_out_not_fatal() {
	let Some(url) = common::database_url() else { return };
	let scratch = common::Scratch::create(&url).await;
	for constraint in ["tenants_origins", "tenants_state"] {
		sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE tenants DROP CONSTRAINT {constraint}")))
			.execute(&scratch.pool)
			.await
			.unwrap();
	}
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, origins) VALUES ('nulls', 'nulls', FALSE, 0, ARRAY[NULL]::TEXT[])")
		.execute(&scratch.pool)
		.await
		.unwrap();
	sqlx::query("INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, state) VALUES ('bogus', 'bogus', FALSE, 0, 'paused')")
		.execute(&scratch.pool)
		.await
		.unwrap();

	let repo = Arc::new(PgScopes::new(scratch.pool.clone()));
	let ids: Vec<String> = repo.scopes().await.expect("the registry reads").into_iter().map(|s| s.id).collect();
	assert_eq!(ids, vec!["invest", "sa"], "the two bad rows are left out");
	assert!(repo.scope("nulls").await.unwrap().is_none());
	assert!(repo.scope("invest").await.unwrap().is_some());
	let allowlist = SignInAllowlist::live(repo, PUBLIC).await.expect("the allowlist builds over a bad row");
	assert!(allowlist.admits(INVEST));

	scratch.drop_database().await;
}
