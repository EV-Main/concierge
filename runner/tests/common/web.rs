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
	let url = super::database_url()?;
	let pool = db::connect_sized(&url, 5).await.expect("connect to Postgres");
	db::migrate(&pool).await.expect("apply migrations");
	let users = Arc::new(PgUsers::new(pool.clone()));
	let mut sign_in = super::sign_in_with_turnstile(&pool, &super::stub_turnstile().await);
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
			governance: Arc::new(PgGovernance::new(pool.clone(), format!("{ORIGIN}/governance"))),
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

#[derive(Default, Clone)]
pub struct Browser {
	pub cookies: Vec<(String, String)>,
}

impl Browser {
	pub fn get(&self, name: &str) -> Option<&str> {
		self.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
	}

	fn header(&self) -> String {
		self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
	}

	fn absorb(&mut self, headers: &HeaderMap) {
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
