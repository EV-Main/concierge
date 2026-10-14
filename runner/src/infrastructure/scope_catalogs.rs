//! Postgres adapter for scope catalogs (`scope_catalogs`, migration 0033): every catalog
//! a namespace ever published, one row per version, the newest in force.

use async_trait::async_trait;
use domain::{
	error::DomainError,
	scope_catalog::{NotificationTopic, ScopeCatalog},
};
use sqlx::{PgExecutor, PgPool};

use crate::ports::{PublishOutcome, ScopeCatalogRepository};

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

fn parse(json: serde_json::Value) -> Result<ScopeCatalog, DomainError> {
	serde_json::from_value(json).map_err(|e| DomainError::Repository(format!("stored scope catalog is unreadable: {e}")))
}

/// The notification topics of every namespace's catalog in force. Shared by the
/// notification adapter, which offers them beside the built-in topics.
pub(crate) async fn current_topics<'e>(executor: impl PgExecutor<'e>) -> Result<Vec<NotificationTopic>, DomainError> {
	let catalogs: Vec<serde_json::Value> = sqlx::query_scalar("SELECT DISTINCT ON (namespace) catalog FROM scope_catalogs ORDER BY namespace, version DESC")
		.fetch_all(executor)
		.await
		.map_err(repo_err)?;
	let mut topics = Vec::new();
	for catalog in catalogs {
		topics.extend(parse(catalog)?.notification_topics);
	}
	Ok(topics)
}

pub struct PgScopeCatalogs {
	pool: PgPool,
}

impl PgScopeCatalogs {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

#[async_trait]
impl ScopeCatalogRepository for PgScopeCatalogs {
	async fn publish(&self, namespace: &str, published_by: &str, catalog: &ScopeCatalog, now: i64) -> Result<PublishOutcome, DomainError> {
		let version = i64::try_from(catalog.version).map_err(|_| DomainError::Validation("a catalog version is at most 2^63-1".into()))?;
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// The namespace may have no tenant row (`bank`) and no catalog yet, so there is no
		// row to lock: two publishers of one namespace serialise on a lock named after it,
		// and the second sees what the first committed.
		sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('scope_catalog:' || $1, 0))")
			.bind(namespace)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		let stored: Option<serde_json::Value> = sqlx::query_scalar("SELECT catalog FROM scope_catalogs WHERE namespace = $1 ORDER BY version DESC LIMIT 1")
			.bind(namespace)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(stored) = stored.map(parse).transpose()? {
			if stored == *catalog {
				return Ok(PublishOutcome::Unchanged);
			}
			if stored.version >= catalog.version {
				return Ok(PublishOutcome::Stale { stored: stored.version });
			}
		}
		let json = serde_json::to_value(catalog).map_err(|e| DomainError::Repository(format!("scope catalog does not encode: {e}")))?;
		sqlx::query("INSERT INTO scope_catalogs (namespace, version, catalog, published_at, published_by) VALUES ($1, $2, $3, $4, $5)")
			.bind(namespace)
			.bind(version)
			.bind(json)
			.bind(now)
			.bind(published_by)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(PublishOutcome::Published)
	}

	async fn current(&self, namespace: &str) -> Result<Option<ScopeCatalog>, DomainError> {
		sqlx::query_scalar::<_, serde_json::Value>("SELECT catalog FROM scope_catalogs WHERE namespace = $1 ORDER BY version DESC LIMIT 1")
			.bind(namespace)
			.fetch_optional(&self.pool)
			.await
			.map_err(repo_err)?
			.map(parse)
			.transpose()
	}
}
