//! Postgres adapter for the scope registry (`tenants` + their `rp_clients`, migration
//! 0031).

use async_trait::async_trait;
use domain::{error::DomainError, scopes::ScopeState};
use sqlx::{FromRow, PgPool, Row};

use crate::ports::{ScopeClientRecord, ScopeRecord, ScopeRepository};

pub struct PgScopes {
	pool: PgPool,
}

impl PgScopes {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

#[derive(sqlx::FromRow)]
struct ScopeRow {
	id: String,
	namespace: String,
	parent: String,
	display_name: String,
	origins: Vec<String>,
	return_paths: Vec<String>,
	observers: Vec<String>,
	state: String,
	version: i64,
	created_at: i64,
	client_ids: Vec<String>,
	audiences: Vec<String>,
	disabled: Vec<bool>,
}

impl TryFrom<ScopeRow> for ScopeRecord {
	type Error = DomainError;

	fn try_from(row: ScopeRow) -> Result<Self, DomainError> {
		let clients = row
			.client_ids
			.into_iter()
			.zip(row.audiences)
			.zip(row.disabled)
			.map(|((client_id, audience), disabled)| ScopeClientRecord { client_id, audience, disabled })
			.collect();
		Ok(Self {
			state: ScopeState::parse(&row.state).map_err(|e| DomainError::Repository(format!("tenant `{}`: {e}", row.id)))?,
			version: u64::try_from(row.version).map_err(|_| DomainError::Repository(format!("tenant `{}` has a negative version", row.id)))?,
			id: row.id,
			namespace: row.namespace,
			parent: row.parent,
			display_name: row.display_name,
			origins: row.origins,
			return_paths: row.return_paths,
			observers: row.observers,
			clients,
			created_at: row.created_at,
		})
	}
}

impl PgScopes {
	/// One statement, so a scope and its clients are read from the same snapshot.
	///
	/// A row that does not decode is skipped at `error!`, never returned as an error: the
	/// registry is read at boot and on every refresh of the sign-in allowlist, and one bad
	/// row must cost that scope its sign-in, not the plane its start. Losing a scope's
	/// origins is the safe direction to fail in.
	async fn read(&self, id: Option<&str>) -> Result<Vec<ScopeRecord>, DomainError> {
		let rows = sqlx::query(
			"SELECT t.id, t.namespace, t.parent, t.display_name, t.origins, t.return_paths, t.observers, t.state, t.version, t.created_at,
			        coalesce(array_agg(c.client_id ORDER BY c.client_id) FILTER (WHERE c.client_id IS NOT NULL), '{}') AS client_ids,
			        coalesce(array_agg(c.audience ORDER BY c.client_id) FILTER (WHERE c.client_id IS NOT NULL), '{}') AS audiences,
			        coalesce(array_agg(c.disabled_at IS NOT NULL ORDER BY c.client_id) FILTER (WHERE c.client_id IS NOT NULL), '{}') AS disabled
			 FROM tenants t LEFT JOIN rp_clients c ON c.tenant_id = t.id
			 WHERE $1::TEXT IS NULL OR t.id = $1
			 GROUP BY t.id
			 ORDER BY t.id COLLATE \"C\"",
		)
		.bind(id)
		.fetch_all(&self.pool)
		.await
		.map_err(|e| DomainError::Repository(format!("scope registry not read: {e}")))?;
		Ok(rows
			.iter()
			.filter_map(|row| {
				let decoded = ScopeRow::from_row(row).map_err(|e| DomainError::Repository(e.to_string())).and_then(ScopeRecord::try_from);
				match decoded {
					Ok(scope) => Some(scope),
					Err(e) => {
						let id: Option<String> = row.try_get("id").ok();
						tracing::error!(scope = ?id, error = %e, "scope registry row does not decode; the scope is left out");
						None
					}
				}
			})
			.collect())
	}
}

#[async_trait]
impl ScopeRepository for PgScopes {
	async fn scopes(&self) -> Result<Vec<ScopeRecord>, DomainError> {
		self.read(None).await
	}

	async fn scope(&self, id: &str) -> Result<Option<ScopeRecord>, DomainError> {
		Ok(self.read(Some(id)).await?.into_iter().next())
	}
}
