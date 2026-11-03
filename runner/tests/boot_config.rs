//! A production boot refuses its configuration before it touches anything (#132). The
//! config checks used to run after the database connection, the migrations and genesis,
//! so a pod with a wrong secret upgraded the schema on its way to crash-looping.
//!
//! Driven through the real binary against a database of its own that nothing migrated:
//! whether `_sqlx_migrations` exists afterwards is the whole assertion.

mod common;

use std::process::{Command, Stdio};

/// Cloudflare's always-pass Turnstile secret: the one `web::is_test_secret` refuses in
/// production, with every other production requirement met.
const TEST_TURNSTILE_SECRET: &str = "1x0000000000000000000000000000000AA";

#[tokio::test]
async fn a_production_boot_with_a_test_turnstile_secret_leaves_the_database_untouched() {
	refused_boot(&[("TURNSTILE_SECRET", TEST_TURNSTILE_SECRET)], "TURNSTILE_SECRET").await;
}

#[tokio::test]
async fn a_production_boot_with_a_step_up_origin_outside_the_site_leaves_the_database_untouched() {
	refused_boot(&[("STEPUP_PROOF_ORIGINS", "https://evinvest.test.evil.example")], "STEPUP_PROOF_ORIGINS").await;
}

#[tokio::test]
async fn a_production_boot_with_a_step_up_pattern_leaves_the_database_untouched() {
	refused_boot(&[("STEPUP_PROOF_ORIGINS", "https://*.evinvest.test")], "STEPUP_PROOF_ORIGINS").await;
}

#[tokio::test]
async fn a_production_boot_with_a_notice_link_base_outside_the_site_leaves_the_database_untouched() {
	refused_boot(&[("NOTICE_LINK_BASES", "invest=https://evinvest.test.evil.example/cabinet")], "NOTICE_LINK_BASES").await;
}

#[tokio::test]
async fn a_boot_with_a_seal_key_that_is_not_32_bytes_leaves_the_database_untouched() {
	let key = v_fixtures::Fixture::parse("//- /seal.key\nc2l4dGVlbiBieXRlcyBvbmx5").write_to_tempdir();
	refused_boot(&[("SECOND_FACTOR_SEAL_KEY_FILE", key.path("seal.key").to_str().unwrap())], "SECOND_FACTOR_SEAL_KEY_FILE").await;
}

/// Boot the binary as production with `overrides` over an otherwise valid configuration
/// and assert it refuses, naming `expected`, before migrating anything.
async fn refused_boot(overrides: &[(&str, &str)], expected: &str) {
	let Some(db) = common::Db::empty().await else { return };

	let output = Command::new(env!("CARGO_BIN_EXE_concierge"))
		// Nothing from the shell the suite runs in: a `.env` or an exported variable would
		// make this a test of that shell. The binary reads `.env` from its working dir.
		.env_clear()
		.current_dir(std::env::temp_dir())
		.envs([
			("APP_ENV", "production"),
			("DATABASE_URL", db.url.as_str()),
			("BRIDGE_SERVICE_TOKEN", "boot-config-bridge-token"),
			("SENTRY_DSN", "http://public@127.0.0.1:9/1"),
			("PUBLIC_ORIGIN", "https://evinvest.test"),
			("SMTP_HOST", "127.0.0.1"),
			("SMTP_USERNAME", "boot"),
			("SMTP_PASSWORD", "boot"),
			("TURNSTILE_SECRET", "a-real-looking-turnstile-secret"),
			("AUTH_SIGNING_KEY_PEM", "unused: refused before it is parsed"),
			("AUTH_SIGNING_KID", "boot"),
			("AUTH_JWKS_JSON", r#"{"keys":[]}"#),
			("GOOGLE_CLIENT_ID", "boot"),
			("GOOGLE_CLIENT_SECRET", "boot"),
			("REDIS_URL", "redis://127.0.0.1:9/15"),
		])
		.envs(overrides.iter().copied())
		.stdin(Stdio::null())
		.output()
		.expect("run the concierge binary");

	let stderr = String::from_utf8_lossy(&output.stderr);
	let migrated: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
		.fetch_one(&db.pool)
		.await
		.expect("read the catalog");

	assert!(!output.status.success(), "the boot is refused: {stderr}");
	assert!(stderr.contains(expected), "refused for {expected}, not for something else: {stderr}");
	assert!(!migrated, "nothing was migrated before the refusal: {stderr}");
}
