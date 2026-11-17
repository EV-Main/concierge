//! Shared preconditions for the integration suites: a database of its own per test, and the
//! one decision about a missing database — skip locally, fail under CI.
//!
//! Each integration test is its own crate, so a suite that uses one half of this module
//! compiles the other half unused — hence the blanket allowance.
#![allow(dead_code)]

pub mod factor;
pub mod web;

/// True under CI: `CI` is set, non-empty and not `"0"`/`"false"`. GitHub Actions and every
/// other runner this repo could land on export `CI=true`.
fn under_ci() -> bool {
	std::env::var("CI").is_ok_and(|value| !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false"))
}

/// A database of its own on the server `DATABASE_URL` names, dropped with this value.
///
/// Every test gets one: ownership, the outbox order, the mail queue and the platform flags
/// are global to a database, so tests sharing one read each other's writes.
pub struct Db {
	pub pool: sqlx::PgPool,
	/// For what needs a connection outside `pool`: a held lock, a spawned binary.
	pub url: String,
	server: String,
	name: String,
}
impl Db {
	pub async fn migrated() -> Option<Self> {
		let db = Self::empty().await?;
		concierge::infrastructure::db::migrate(&db.pool).await.expect("apply migrations");
		Some(db)
	}

	/// Nothing migrated: for the suites asserting what a migration or a boot does to one.
	///
	/// `None` without `DATABASE_URL`: locally a skip, so a DB-less `cargo test` still passes.
	/// Under CI a panic, because the skip is otherwise INVISIBLE: libtest swallows a passing
	/// test's output unless `--nocapture` is given, so a fully skipped suite prints exactly the
	/// "N passed" a real run prints and the only tell is the wall time.
	pub async fn empty() -> Option<Self> {
		let server = match std::env::var("DATABASE_URL").ok().filter(|value| !value.is_empty()) {
			Some(url) => url,
			None if under_ci() => panic!("CI=true and DATABASE_URL unset: this suite would assert nothing. Point it at a real Postgres, or unset CI to skip locally."),
			None => {
				eprintln!("SKIPPED: DATABASE_URL unset — this test asserted nothing (only visible under --nocapture)");
				return None;
			}
		};
		let name = format!("concierge_test_{}", uuid::Uuid::new_v4().simple());
		let mut admin = <sqlx::PgConnection as sqlx::Connection>::connect(&server).await.expect("connect to Postgres");
		sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
			.execute(&mut admin)
			.await
			.expect("create the test database");
		sqlx::Connection::close(admin).await.expect("disconnect");
		let (base, query) = server.split_once('?').map_or((server.as_str(), None), |(base, query)| (base, Some(query)));
		let (host, _) = base.rsplit_once('/').expect("DATABASE_URL names a database");
		let url = match query {
			Some(query) => format!("{host}/{name}?{query}"),
			None => format!("{host}/{name}"),
		};
		let pool = concierge::infrastructure::db::connect_sized(&url, 10).await.expect("connect to the test database");
		Some(Self { pool, url, server, name })
	}
}
impl Drop for Db {
	/// On a thread of its own: a runtime cannot be blocked on from inside the test's.
	fn drop(&mut self) {
		let (server, name) = (&self.server, &self.name);
		let dropped = std::thread::scope(|scope| {
			scope
				.spawn(|| {
					tokio::runtime::Builder::new_current_thread()
						.enable_all()
						.build()
						.expect("a runtime for the drop")
						.block_on(async {
							let mut admin = <sqlx::PgConnection as sqlx::Connection>::connect(server).await.expect("connect to Postgres");
							sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name} WITH (FORCE)")))
								.execute(&mut admin)
								.await
								.expect("drop the test database");
						})
				})
				.join()
		});
		// A second panic while unwinding aborts, hiding the failure that started it.
		if dropped.is_err() && !std::thread::panicking() {
			panic!("test database {name} was not dropped");
		}
	}
}

/// A Google sign-in as `UserDirectoryRepository::resolve` receives it, with a fresh
/// subject and a fresh address: one verified mailbox opens one account, so two fixtures
/// sharing an address would silently be one person. `tag` keeps the address readable.
pub fn google(tag: &str, verified: bool) -> domain::auth::ProvenIdentity {
	google_as(
		&format!("{tag}-{}", uuid::Uuid::new_v4()),
		&format!("{tag}-{}@example.com", uuid::Uuid::new_v4().simple()),
		verified,
	)
}

/// A Google sign-in by a named subject and address — for the tests about what those do.
pub fn google_as(subject: &str, email: &str, verified: bool) -> domain::auth::ProvenIdentity {
	domain::auth::ProvenIdentity {
		provider: Some((domain::auth::Provider::Google, subject.to_owned())),
		email: domain::users::Email::parse(email).expect("a test address parses"),
		email_proven: verified,
	}
}

/// The account-less subscribe budget of every suite's web state, per client address. Tests
/// driving the router without a socket all share the empty address's bucket.
pub const SUBSCRIBES_PER_HOUR: u32 = 50;

/// The sign-in half of a web state that answers no credential request: the Turnstile it
/// names refuses every connection.
pub fn inert_sign_in(pool: &sqlx::PgPool) -> concierge::web::SignInDeps {
	sign_in_with_turnstile(pool, "http://127.0.0.1:9/siteverify")
}

pub fn sign_in_with_turnstile(pool: &sqlx::PgPool, turnstile: &str) -> concierge::web::SignInDeps {
	concierge::web::SignInDeps {
		providers: Vec::new(),
		turnstile: concierge::web::Turnstile::new("test-secret".into(), turnstile.into()),
		credentials: std::sync::Arc::new(concierge::infrastructure::credentials::PgCredentials::new(pool.clone())),
		mail_wake: std::sync::Arc::new(tokio::sync::Notify::new()),
		allowlist: std::sync::Arc::new(
			concierge::web::allowlist::SignInAllowlist::fixed(WEBAUTHN_ORIGIN, concierge::web::origins::ScopeOrigins::none()).expect("a test origin is a relying party"),
		),
		subscribe_limiter: std::sync::Arc::new(concierge::notification::RateLimiter::new(std::time::Duration::from_secs(3600), SUBSCRIBES_PER_HOUR)),
		stepup: None,
		second_factor: None,
	}
}

/// A configured issuer with a throwaway Ed25519 key, reading accounts from `users` over
/// the same provisioner channel the runner wires.
pub async fn signing_auth(users: std::sync::Arc<dyn concierge::ports::UserDirectoryRepository>) -> evconcierge_auth::AuthService {
	let (provisioner, rx) = evconcierge_auth::provisioner_channel();
	tokio::spawn(concierge::directory::run_provisioner(
		rx,
		users,
		std::sync::Arc::new(concierge::authz::BreakGlass::new(Vec::new())),
	));
	issuer(provisioner).await
}

/// [`signing_auth`] over whatever answers `provisioner`.
pub async fn issuer(provisioner: evconcierge_auth::Provisioner) -> evconcierge_auth::AuthService {
	const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
	const JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
	let config = evconcierge_auth::AuthConfig {
		issuer: "https://auth.concierge.test".into(),
		client_audience: "concierge".into(),
		service_audience: "concierge-services".into(),
		access_ttl_secs: 900,
		refresh_ttl_secs: 3600,
		max_session_secs: 7_776_000,
		idle_timeout_secs: 0,
		service_ttl_secs: 300,
		signing: Some(evconcierge_auth::SigningConfig {
			signing_key_pem: PEM.into(),
			kid: "test-kid".into(),
			jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
		}),
		google: None,
		github: None,
	};
	evconcierge_auth::AuthService::try_new(config, provisioner).await.expect("auth service")
}

/// A Turnstile siteverify that passes exactly the token `human`, solved on the suites'
/// own host — and `elsewhere`, solved by a person on a host that is not ours. Returns its URL.
pub async fn stub_turnstile() -> String {
	use axum::{Form, Json, Router, routing::post};
	async fn verify(Form(form): Form<std::collections::HashMap<String, String>>) -> Json<serde_json::Value> {
		Json(match form.get("response").map(String::as_str) {
			Some("human") => serde_json::json!({ "success": true, "hostname": "evinvest.test" }),
			Some("elsewhere") => serde_json::json!({ "success": true, "hostname": "evil.example" }),
			_ => serde_json::json!({ "success": false }),
		})
	}
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind the turnstile stub");
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, Router::new().route("/siteverify", post(verify))).await });
	format!("http://{addr}/siteverify")
}

/// The origin every suite's web state is served from, as WebAuthn sees it.
pub const WEBAUTHN_ORIGIN: &str = "https://evinvest.test";
