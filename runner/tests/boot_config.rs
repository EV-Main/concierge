//! A production boot refuses its configuration before it touches anything (#132). The
//! config checks used to run after the database connection, the migrations and genesis,
//! so a pod with a wrong secret upgraded the schema on its way to crash-looping.
//!
//! Driven through the real binary against a database of its own that nothing migrated:
//! whether `_sqlx_migrations` exists afterwards is the whole assertion.

mod common;

use std::process::{Command, Stdio};

use sqlx::{Connection, PgConnection};

/// Cloudflare's always-pass Turnstile secret: the one `web::is_test_secret` refuses in
/// production, with every other production requirement met.
const TEST_TURNSTILE_SECRET: &str = "1x0000000000000000000000000000000AA";

/// The scratch database's URL: `url` with its database name swapped.
fn with_database(url: &str, name: &str) -> String {
	let (base, query) = url.split_once('?').map_or((url, None), |(base, query)| (base, Some(query)));
	let (server, _) = base.rsplit_once('/').expect("DATABASE_URL names a database");
	match query {
		Some(query) => format!("{server}/{name}?{query}"),
		None => format!("{server}/{name}"),
	}
}

#[tokio::test]
async fn a_production_boot_with_a_test_turnstile_secret_leaves_the_database_untouched() {
	refused_boot(TEST_TURNSTILE_SECRET, None, None, "TURNSTILE_SECRET").await;
}

#[tokio::test]
async fn a_production_boot_with_a_step_up_origin_outside_the_site_leaves_the_database_untouched() {
	refused_boot("a-real-looking-turnstile-secret", Some("https://evinvest.test.evil.example"), None, "STEPUP_PROOF_ORIGINS").await;
}

#[tokio::test]
async fn a_production_boot_with_a_step_up_pattern_leaves_the_database_untouched() {
	refused_boot("a-real-looking-turnstile-secret", Some("https://*.evinvest.test"), None, "STEPUP_PROOF_ORIGINS").await;
}

#[tokio::test]
async fn a_production_boot_with_a_notice_link_base_outside_the_site_leaves_the_database_untouched() {
	refused_boot(
		"a-real-looking-turnstile-secret",
		None,
		Some("invest=https://evinvest.test.evil.example/cabinet"),
		"NOTICE_LINK_BASES",
	)
	.await;
}

/// Boot the binary as production with one invalid setting and assert it refuses, naming
/// `expected`, before migrating anything.
async fn refused_boot(turnstile_secret: &str, stepup_origins: Option<&str>, notice_link_bases: Option<&str>, expected: &str) {
	let Some(url) = common::database_url() else { return };
	let name = format!("concierge_boot_{}", uuid::Uuid::new_v4().simple());
	let mut admin = PgConnection::connect(&url).await.expect("connect to Postgres");
	sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
		.execute(&mut admin)
		.await
		.expect("create the scratch database");
	let scratch = with_database(&url, &name);

	let output = Command::new(env!("CARGO_BIN_EXE_concierge"))
		// Nothing from the shell the suite runs in: a `.env` or an exported variable would
		// make this a test of that shell. The binary reads `.env` from its working dir.
		.env_clear()
		.current_dir(std::env::temp_dir())
		.envs([
			("APP_ENV", "production"),
			("DATABASE_URL", scratch.as_str()),
			("BRIDGE_SERVICE_TOKEN", "boot-config-bridge-token"),
			("SENTRY_DSN", "http://public@127.0.0.1:9/1"),
			("PUBLIC_ORIGIN", "https://evinvest.test"),
			("SMTP_HOST", "127.0.0.1"),
			("SMTP_USERNAME", "boot"),
			("SMTP_PASSWORD", "boot"),
			("TURNSTILE_SECRET", turnstile_secret),
			("STEPUP_PROOF_ORIGINS", stepup_origins.unwrap_or_default()),
			("NOTICE_LINK_BASES", notice_link_bases.unwrap_or_default()),
			("AUTH_SIGNING_KEY_PEM", "unused: refused before it is parsed"),
			("AUTH_SIGNING_KID", "boot"),
			("AUTH_JWKS_JSON", r#"{"keys":[]}"#),
			("GOOGLE_CLIENT_ID", "boot"),
			("GOOGLE_CLIENT_SECRET", "boot"),
			("REDIS_URL", "redis://127.0.0.1:9/15"),
		])
		.stdin(Stdio::null())
		.output()
		.expect("run the concierge binary");

	let stderr = String::from_utf8_lossy(&output.stderr);
	let mut probe = PgConnection::connect(&scratch).await.expect("connect to the scratch database");
	let migrated: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
		.fetch_one(&mut probe)
		.await
		.expect("read the catalog");
	probe.close().await.expect("disconnect");
	sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name} WITH (FORCE)")))
		.execute(&mut admin)
		.await
		.expect("drop the scratch database");

	assert!(!output.status.success(), "the boot is refused: {stderr}");
	assert!(stderr.contains(expected), "refused for {expected}, not for something else: {stderr}");
	assert!(!migrated, "nothing was migrated before the refusal: {stderr}");
}
