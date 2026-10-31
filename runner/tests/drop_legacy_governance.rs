//! Migration 0051 drops the legacy governance tables only while they are empty, and its
//! down step puts them back. Runs on a database of its own, created and dropped here, so
//! moving the schema back and forth never touches the one the other suites share.

use std::str::FromStr;

use concierge::{infrastructure::users::PgUsers, ports::UserDirectoryRepository};
use sqlx::{
	Connection, PgConnection, PgPool,
	migrate::{MigrateError, Migrator},
	postgres::{PgConnectOptions, PgPoolOptions},
};

mod common;

static MIGRATOR: Migrator = sqlx::migrate!();
const BEFORE: i64 = 50;
const LEGACY: [&str; 8] = [
	"owner_removal",
	"owner_removal_peer",
	"owner_removal_token",
	"owner_admission",
	"owner_admission_peer",
	"user_proposal",
	"user_proposal_peer",
	"governance_event",
];

/// Each step on a connection of its own, closed after it: a failed migration returns with
/// sqlx's session advisory lock still held on the connection it ran on.
async fn step(db: &PgConnectOptions, run: impl AsyncFnOnce(&mut PgConnection) -> Result<(), MigrateError>) -> Result<(), MigrateError> {
	let mut conn = PgConnection::connect_with(db).await.expect("connect");
	let result = run(&mut conn).await;
	conn.close().await.expect("close");
	result
}

async fn present(pool: &PgPool) -> Vec<&'static str> {
	let mut found = Vec::new();
	for table in LEGACY {
		let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL").bind(table).fetch_one(pool).await.unwrap();
		if exists {
			found.push(table);
		}
	}
	found
}

async fn applied(pool: &PgPool) -> i64 {
	sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success").fetch_one(pool).await.unwrap()
}

async fn proposal_fk(pool: &PgPool) -> bool {
	sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'admin_action_proposal_id_fkey')")
		.fetch_one(pool)
		.await
		.unwrap()
}

#[tokio::test]
async fn the_legacy_tables_go_only_empty_and_come_back_on_the_way_down() {
	let Some(url) = common::database_url() else { return };
	let server = PgConnectOptions::from_str(&url).expect("DATABASE_URL parses");
	let name = format!("concierge_m0051_{}", uuid::Uuid::new_v4().simple());
	let mut admin = PgConnection::connect_with(&server).await.expect("connect to the server");
	sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
		.execute(&mut admin)
		.await
		.expect("a database of our own");
	let db = server.clone().database(&name);
	let pool = PgPoolOptions::new().max_connections(2).connect_with(db.clone()).await.expect("connect to it");

	step(&db, async |c| MIGRATOR.run_to(BEFORE, c).await).await.expect("the schema before 0051");
	let users = PgUsers::new(pool.clone());
	let subject = users.resolve(common::google("m51-subject", true), 0).await.expect("provision").id();
	let initiator = users.resolve(common::google("m51-initiator", true), 0).await.expect("provision").id();
	// Decided, not open: history is refused as firmly as a live proposal.
	sqlx::query(
		"INSERT INTO user_proposal (id, kind, subject_user_id, initiator_user_id, reason, state, owner_count, threshold, created_at, expires_at, decided_at) \
		 VALUES ($1, 'suspension', $2, $3, 'cause', 'rejected', 3, 2, 1, 2, 2)",
	)
	.bind(uuid::Uuid::new_v4())
	.bind(subject.raw())
	.bind(initiator.raw())
	.execute(&pool)
	.await
	.expect("a legacy row");

	let refused = step(&db, async |c| MIGRATOR.run(c).await).await.expect_err("0051 must refuse while a legacy row exists");
	assert!(refused.to_string().contains("user_proposal"), "the refusal names the table: {refused}");
	assert_eq!(applied(&pool).await, BEFORE, "nothing was recorded as applied");
	assert_eq!(present(&pool).await, LEGACY, "and nothing was dropped");
	assert!(proposal_fk(&pool).await);

	sqlx::query("DELETE FROM user_proposal").execute(&pool).await.unwrap();
	step(&db, async |c| MIGRATOR.run(c).await).await.expect("empty, they go");
	assert!(present(&pool).await.is_empty(), "{:?}", present(&pool).await);
	assert!(!proposal_fk(&pool).await, "the foreign key into user_proposal goes with it");
	let column: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'admin_action' AND column_name = 'proposal_id')")
		.fetch_one(&pool)
		.await
		.unwrap();
	assert!(column, "the column stays for the binary from before 0051");

	step(&db, async |c| MIGRATOR.undo(c, BEFORE).await).await.expect("the down step");
	assert_eq!(present(&pool).await, LEGACY, "every table is back");
	assert!(proposal_fk(&pool).await, "and the foreign key into user_proposal");
	step(&db, async |c| MIGRATOR.run(c).await).await.expect("and up again");

	pool.close().await;
	sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name} WITH (FORCE)")))
		.execute(&mut admin)
		.await
		.expect("drop it");
}
