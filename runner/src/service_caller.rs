//! Who is calling a service-credential RPC (`docs/SCOPES-AND-APPROVALS.md` §2): the money
//! plane by the shared bridge token, or a relying party by its client id and secret.
//!
//! The answer comes from metadata alone — never from a request field a caller could widen —
//! and both secrets are compared in constant time: the bridge token by
//! [`support::authenticate_service`], the client secret as a fixed-width SHA-256 digest
//! against the one `rp_clients` stores. An unknown client, a disabled one, one without a
//! secret and a wrong secret are the same `UNAUTHENTICATED`.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tonic::{Request, Status};

use crate::{
	ports::RelyingPartyRepository,
	support::{authenticate_service, bearer_token},
};

/// The metadata key naming the relying party; its secret rides in `authorization`.
pub const CLIENT_ID_HEADER: &str = "x-ev-client-id";

/// The namespace the money plane speaks for. It has no tenant row; its scope is `main`.
pub const BANK_NAMESPACE: &str = "bank";

/// What `published_by` records for the money plane, which is no client.
pub const BRIDGE_PUBLISHER: &str = "bridge";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceCaller {
	/// The money plane: namespace `bank`, scope `main`, every stream unfiltered.
	Bridge,
	Client(ClientCaller),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCaller {
	pub client_id: String,
	/// The `aud` of the access tokens it is issued for its users.
	pub audience: String,
	pub scope: String,
	pub namespace: String,
	/// Its scope is CLOSED: the history stays readable on every stream, nothing new is
	/// accepted from it.
	pub scope_closed: bool,
}

impl ServiceCaller {
	pub fn namespace(&self) -> &str {
		match self {
			Self::Bridge => BANK_NAMESPACE,
			Self::Client(client) => &client.namespace,
		}
	}

	pub fn publisher(&self) -> &str {
		match self {
			Self::Bridge => BRIDGE_PUBLISHER,
			Self::Client(client) => &client.client_id,
		}
	}
}

#[derive(Clone)]
pub struct ServiceCallers {
	/// `None` ⇒ the bridge token is not configured and the money plane is refused
	/// (fail-closed), while relying parties still authenticate by their own secret.
	bridge_token: Option<Arc<str>>,
	clients: Arc<dyn RelyingPartyRepository>,
}

impl ServiceCallers {
	pub fn new(bridge_token: Option<String>, clients: Arc<dyn RelyingPartyRepository>) -> Self {
		Self {
			bridge_token: bridge_token.map(|t| Arc::from(t.as_str())),
			clients,
		}
	}

	/// `seam` names the service in the refusal, as [`authenticate_service`] does.
	pub async fn authenticate<T>(&self, request: &Request<T>, seam: &str) -> Result<ServiceCaller, Status> {
		let Some(client_id) = request.metadata().get(CLIENT_ID_HEADER) else {
			authenticate_service(self.bridge_token.as_ref(), request, seam)?;
			return Ok(ServiceCaller::Bridge);
		};
		let refused = || Status::unauthenticated(format!("invalid {seam} client credential"));
		let client_id = client_id.to_str().map_err(|_| refused())?;
		let secret = bearer_token(request).ok_or_else(refused)?;
		let client = self
			.clients
			.client(client_id)
			.await
			.map_err(|err| {
				tracing::error!(%err, "{seam}: relying party registry unreadable");
				Status::unavailable("internal error")
			})?
			.ok_or_else(refused)?;
		let presented: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
		// Both sides are 32-byte digests once the stored one is that long, so the length
		// guard `ct_eq` needs is the comparison of lengths right here.
		let matches = client
			.secret_hash
			.as_deref()
			.is_some_and(|stored| stored.len() == presented.len() && bool::from(stored.ct_eq(&presented)));
		if !matches || client.disabled {
			// Debug, not Display: this is the caller's own string and may carry newlines.
			tracing::warn!(client_id = ?client_id.chars().take(32).collect::<String>(), "{seam}: client authentication failed");
			return Err(refused());
		}
		Ok(ServiceCaller::Client(ClientCaller {
			client_id: client.client_id,
			audience: client.audience,
			scope: client.scope,
			namespace: client.namespace,
			scope_closed: client.scope_closed,
		}))
	}
}
