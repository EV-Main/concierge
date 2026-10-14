//! `scopes` module — `ScopeRegistry`, the read side of the scope registry
//! (`docs/SCOPES-AND-APPROVALS.md` §3).
//!
//! Mounted inside the user auth layer. Any verified caller reads it, with no permission:
//! a scope's hosts, clients and observers are what every direction already has to know to
//! talk to the others, and nothing here names a person. A relying party's restricted token
//! never reaches it — the layer admits that token on `GetMe` alone.
//!
//! It reads the same port the sign-in allowlist (`web::allowlist`) refreshes from, so both
//! describe one registry; the RPC reads it on every call, the allowlist at most
//! `REFRESH_EVERY` behind. They do NOT share a rule for a malformed row: the RPC answers
//! every row as stored — closed scopes, and an origin or path that breaks the shape rules,
//! included — while the allowlist leaves such a row out and reports it
//! (`web::origins::ScopeOrigins::from_scopes`). The registry's CHECKs are what keep such a
//! row out of the table; a consumer that signs people in or redirects on this answer
//! applies the shape rules itself (`domain::scopes`).
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::scopes::{ROOT, ScopeState};
use evconcierge_auth::claims_of;
use evconcierge_contracts::concierge::v1::{self as cc, GetScopeRequest, ListScopesRequest, ListScopesResponse, ScopeClient, scope_registry_server::ScopeRegistry as ScopeRegistryRpc};
use tonic::{Request, Response, Status};

use crate::{
	ports::{ScopeRecord, ScopeRepository},
	support::domain_to_status,
};

#[derive(Clone)]
pub struct ScopeRegistry {
	repo: Arc<dyn ScopeRepository>,
}

impl ScopeRegistry {
	pub fn new(repo: Arc<dyn ScopeRepository>) -> Self {
		Self { repo }
	}

	async fn registered(&self) -> Result<Vec<cc::Scope>, Status> {
		Ok(self.repo.scopes().await.map_err(domain_to_status)?.into_iter().map(wire).collect())
	}
}

/// `main` has no row: its permissions are the seats', it signs nobody in through a
/// client, and its own host is `PUBLIC_ORIGIN`, which is not a scope origin.
fn root() -> cc::Scope {
	cc::Scope {
		id: ROOT.to_owned(),
		state: cc::ScopeState::Active as i32,
		..Default::default()
	}
}

pub(crate) fn wire(scope: ScopeRecord) -> cc::Scope {
	cc::Scope {
		id: scope.id,
		namespace: scope.namespace,
		parent: scope.parent,
		display_name: scope.display_name,
		origins: scope.origins,
		clients: scope
			.clients
			.into_iter()
			.map(|c| ScopeClient {
				client_id: c.client_id,
				audience: c.audience,
				disabled: c.disabled,
			})
			.collect(),
		observers: scope.observers,
		created_at: scope.created_at,
		version: scope.version,
		state: match scope.state {
			ScopeState::Active => cc::ScopeState::Active,
			ScopeState::Frozen => cc::ScopeState::Frozen,
			ScopeState::Closed => cc::ScopeState::Closed,
		} as i32,
		return_paths: scope.return_paths,
	}
}

#[tonic::async_trait]
impl ScopeRegistryRpc for ScopeRegistry {
	async fn list_scopes(&self, request: Request<ListScopesRequest>) -> Result<Response<ListScopesResponse>, Status> {
		// Defense in depth against an unwrapped mount: the layer injects claims or refuses.
		claims_of(&request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		let mut scopes = vec![root()];
		scopes.extend(self.registered().await?);
		Ok(Response::new(ListScopesResponse { scopes }))
	}

	async fn get_scope(&self, request: Request<GetScopeRequest>) -> Result<Response<cc::Scope>, Status> {
		claims_of(&request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		let id = &request.get_ref().scope;
		if id == ROOT {
			return Ok(Response::new(root()));
		}
		self.repo
			.scope(id)
			.await
			.map_err(domain_to_status)?
			.map(|scope| Response::new(wire(scope)))
			.ok_or_else(|| Status::not_found("no such scope"))
	}
}
