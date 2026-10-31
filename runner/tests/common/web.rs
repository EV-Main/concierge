//! A browser against the auth web surface: the router over a real Postgres and Redis, a
//! Turnstile that passes the token `human`, the live scope allowlist, and a cookie jar.

use std::sync::Arc;

use axum::{
	Router,
	body::Body,
	http::{HeaderMap, Method, Request, StatusCode, header},
};
use concierge::{
	infrastructure::{db, governance::PgGovernance, kyc::cases::PgKycCases, notifications::PgNotifications, scopes::PgScopes, users::PgUsers},
	web::{self, KycDeps, allowlist::SignInAllowlist},
};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

pub const ORIGIN: &str = super::WEBAUTHN_ORIGIN;
/// Seeded by migration 0031.
pub const INVEST: &str = "https://invest.evinvest.ltd";

pub struct Surface {
	pub router: Router,
	pub pool: PgPool,
}

pub async fn surface() -> Option<Surface> {
	surface_with(None, false).await
}

/// [`surface`] with `/auth/second-factor/*` mounted under the suite's throwaway seal key,
/// which every surface of the suite shares, as replicas do.
pub async fn surface_with_second_factor(stepup: Option<web::stepup::StepupDeps>) -> Option<Surface> {
	surface_with(stepup, true).await
}

/// A seal key file of 32 random bytes, as `SECOND_FACTOR_SEAL_KEY_FILE` names one: made
/// once per suite.
pub fn seal_key_file() -> &'static std::path::Path {
	static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
	PATH.get_or_init(|| {
		use base64::{Engine, engine::general_purpose::STANDARD};
		let mut key = [0u8; 32];
		getrandom::fill(&mut key).unwrap();
		let path = std::env::temp_dir().join(format!("concierge-seal-{}", uuid::Uuid::new_v4().simple()));
		std::fs::write(&path, STANDARD.encode(key)).unwrap();
		path
	})
}

async fn surface_with(stepup: Option<web::stepup::StepupDeps>, second_factor: bool) -> Option<Surface> {
	let url = super::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users = Arc::new(PgUsers::new(pool.clone()));
	let mut sign_in = super::sign_in_with_turnstile(&pool, &super::stub_turnstile().await);
	sign_in.stepup = stepup;
	sign_in.second_factor = second_factor.then(|| web::second_factor::SecondFactorDeps {
		seal: concierge::second_factor::SealKey::from_file(seal_key_file().to_str().unwrap()).expect("a fresh key file reads"),
		store: Arc::new(concierge::infrastructure::second_factors::PgSecondFactors::new(pool.clone())),
	});
	sign_in.allowlist = Arc::new(SignInAllowlist::live(Arc::new(PgScopes::new(pool.clone())), ORIGIN).await.expect("read the scope registry"));
	let state = web::WebState::try_new(
		super::signing_auth(users.clone()).await,
		ORIGIN.to_string(),
		false,
		sign_in,
		KycDeps {
			users,
			cases: Arc::new(PgKycCases::new(pool.clone())),
			notifications: Arc::new(PgNotifications::new(pool.clone())),
			governance: Arc::new(PgGovernance::new(pool.clone())),
			provider: None,
			support_email: "support@evinvest.test".into(),
			case_ttl_secs: 86_400,
		},
		None,
	)
	.await
	.expect("build the web state");
	Some(Surface { router: web::router(state), pool })
}

#[derive(Clone, Default)]
pub struct Browser {
	pub cookies: Vec<(String, String)>,
}

impl Browser {
	pub fn get(&self, name: &str) -> Option<&str> {
		self.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
	}

	pub fn header(&self) -> String {
		self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
	}

	pub fn absorb(&mut self, headers: &HeaderMap) {
		for raw in headers.get_all(header::SET_COOKIE) {
			let pair = raw.to_str().unwrap().split(';').next().unwrap();
			let (name, value) = pair.split_once('=').unwrap();
			self.cookies.retain(|(k, _)| k != name);
			if !value.is_empty() {
				self.cookies.push((name.to_owned(), value.to_owned()));
			}
		}
	}
}

pub struct Answer {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: Value,
}

impl Surface {
	/// A request as `browser` sends it from `origin`: its cookies, and the CSRF header
	/// whenever it can read the CSRF cookie (`with_csrf`).
	pub async fn send(&self, method: Method, path: &str, origin: &str, body: Option<Value>, browser: &mut Browser, with_csrf: bool) -> Answer {
		let mut request = Request::builder().method(method).uri(path).header(header::ORIGIN, origin);
		if !browser.cookies.is_empty() {
			request = request.header(header::COOKIE, browser.header());
		}
		if with_csrf && let Some(csrf) = browser.get("ev_csrf") {
			request = request.header("x-ev-csrf", csrf.to_owned());
		}
		if body.is_some() {
			request = request.header(header::CONTENT_TYPE, "application/json");
		}
		let response = self
			.router
			.clone()
			.oneshot(request.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string()))).unwrap())
			.await
			.unwrap();
		browser.absorb(response.headers());
		let (status, headers) = (response.status(), response.headers().clone());
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
		Answer {
			status,
			headers,
			body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
		}
	}

	pub async fn post(&self, path: &str, origin: &str, body: Value, browser: &mut Browser) -> Answer {
		self.send(Method::POST, path, origin, Some(body), browser, true).await
	}

	/// A JSON `fetch` a page on `origin` makes with the browser's cookies: marked
	/// `Sec-Fetch-Site: same-site` by the browser, and carrying no CSRF header, which a page
	/// off `PUBLIC_ORIGIN` cannot read.
	pub async fn page_post(&self, path: &str, origin: &str, body: Value, browser: &mut Browser) -> Answer {
		let mut request = Request::builder()
			.method(Method::POST)
			.uri(path)
			.header(header::ORIGIN, origin)
			.header("sec-fetch-site", "same-site")
			.header(header::CONTENT_TYPE, "application/json");
		if !browser.cookies.is_empty() {
			request = request.header(header::COOKIE, browser.header());
		}
		let response = self.router.clone().oneshot(request.body(Body::from(body.to_string())).unwrap()).await.unwrap();
		browser.absorb(response.headers());
		let (status, headers) = (response.status(), response.headers().clone());
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
		Answer {
			status,
			headers,
			body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
		}
	}

	pub async fn get(&self, path: &str, browser: &mut Browser) -> Answer {
		self.send(Method::GET, path, ORIGIN, None, browser, false).await
	}

	/// The plaintext of the newest code of `purpose` (`login`, `verify`) queued for `email`.
	pub async fn mailed_code(&self, email: &str, purpose: &str) -> String {
		sqlx::query_scalar("SELECT payload->>'code' FROM notification_deliveries WHERE kind = 'email_code' AND recipient = $1 AND payload->>'purpose' = $2 ORDER BY id DESC LIMIT 1")
			.bind(email)
			.bind(purpose)
			.fetch_one(&self.pool)
			.await
			.expect("a code was queued")
	}

	/// Sign in with an emailed code from this plane's origin.
	pub async fn sign_in_with_code(&self, email: &str, browser: &mut Browser) -> Answer {
		let asked = self
			.post(
				"/auth/code/request",
				ORIGIN,
				serde_json::json!({ "email": email, "turnstileToken": "human" }),
				&mut Browser::default(),
			)
			.await;
		assert_eq!(asked.status, StatusCode::OK, "{:?}", asked.body);
		let code = self.mailed_code(email, "login").await;
		self.post("/auth/code/verify", ORIGIN, serde_json::json!({ "email": email, "code": code }), browser).await
	}
}

pub fn address(tag: &str) -> String {
	format!("{tag}-{}@example.com", uuid::Uuid::new_v4().simple())
}

/// Age the session's sign-in by `secs` as if it were that old: the family's `auth_time`
/// in Redis, and the stored access token expired so the next read mints one carrying it.
/// `false` (the test returns) when no Redis is configured.
pub async fn age_session(browser: &Browser, secs: i64) -> bool {
	let Some(url) = std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) else {
		return false;
	};
	let mut conn = redis::Client::open(url).unwrap().get_multiplexed_async_connection().await.unwrap();
	let key = format!("websess:{}", browser.get("ev_session").unwrap());
	let refresh: String = redis::cmd("HGET").arg(&key).arg("refresh_token").query_async(&mut conn).await.unwrap();
	let family = refresh.split('.').next().unwrap();
	let old = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 - secs;
	let _: () = redis::cmd("HSET")
		.arg(format!("refresh:fam:{family}"))
		.arg("auth_time")
		.arg(old)
		.query_async(&mut conn)
		.await
		.unwrap();
	let _: () = redis::cmd("HSET").arg(&key).arg("access_expires_at").arg(0).query_async(&mut conn).await.unwrap();
	true
}
