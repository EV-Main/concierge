//! The live sign-in allowlist: the scope origins the sign-in routes, the passkey verifier,
//! OAuth `returnTo` and the MFE bundles answer.
//!
//! Live and not a boot snapshot, because the answer must follow the registry: a scope
//! that is CLOSED, or an origin that is removed, has to stop being let in without anyone
//! restarting the plane. Refreshed in the background ([`run_refresh`]) and never on a
//! request's path, so a slow or unreachable database costs a request nothing — it is
//! answered from the snapshot in hand.

use std::{
	sync::{Arc, RwLock},
	time::Duration,
};

use color_eyre::eyre::{Context, Result};
use webauthn_rs::Webauthn;

use crate::{
	ports::{ScopeRecord, ScopeRepository},
	web::{origins::ScopeOrigins, passkey},
};

/// How stale the allowlist may be. A closed scope's host keeps signing in for at most
/// this long.
pub const REFRESH_EVERY: Duration = Duration::from_secs(30);

/// One reading of the registry, and the passkey verifier built from it. The two are one
/// value so a ceremony never meets origins from one reading and a verifier from another.
pub struct Snapshot {
	pub origins: ScopeOrigins,
	pub webauthn: Arc<Webauthn>,
	/// `(id, version)` of every scope it was built from. Every change to a scope bumps
	/// its version (migration 0031's triggers), so an equal key means nothing to rebuild.
	key: Vec<(String, u64)>,
}

pub struct SignInAllowlist {
	public_origin: String,
	/// `None` ⇒ never refreshed: tests, and a plane with nothing to read it from.
	source: Option<Arc<dyn ScopeRepository>>,
	current: RwLock<Arc<Snapshot>>,
}

impl SignInAllowlist {
	/// A plane that cannot read the registry at boot does not start: it would otherwise
	/// begin by refusing every scope host it is meant to serve.
	pub async fn live(repo: Arc<dyn ScopeRepository>, public_origin: &str) -> Result<Self> {
		let scopes = repo.scopes().await.context("failed to read the scope registry")?;
		let snapshot = snapshot(public_origin, &scopes)?;
		Ok(Self::new(public_origin, Some(repo), snapshot))
	}

	pub fn fixed(public_origin: &str, origins: ScopeOrigins) -> Result<Self> {
		let webauthn = Arc::new(passkey::verifier(public_origin, origins.origins())?);
		Ok(Self::new(public_origin, None, Snapshot { origins, webauthn, key: Vec::new() }))
	}

	fn new(public_origin: &str, source: Option<Arc<dyn ScopeRepository>>, snapshot: Snapshot) -> Self {
		Self {
			public_origin: public_origin.trim_end_matches('/').to_owned(),
			source,
			current: RwLock::new(Arc::new(snapshot)),
		}
	}

	pub fn current(&self) -> Arc<Snapshot> {
		// The value is replaced in one assignment, so a lock poisoned by a panic elsewhere
		// still guards a whole snapshot.
		self.current.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
	}

	pub fn admits(&self, origin: &str) -> bool {
		origin == self.public_origin || self.current().origins.admits(origin)
	}

	/// Whether `host` — a bare hostname, as Turnstile reports where a challenge was solved
	/// — is the public origin's or a signing-in scope's.
	pub fn admits_host(&self, host: &str) -> bool {
		host_of(&self.public_origin) == Some(host) || self.current().origins.origins().any(|origin| host_of(origin) == Some(host))
	}

	/// Read the registry and swap the snapshot when a scope changed. Returns whether it
	/// did. A failed read keeps the snapshot in hand: an outage of the registry must not
	/// sign everyone out of every scope host.
	pub async fn refresh(&self) -> bool {
		let Some(repo) = &self.source else {
			return false;
		};
		let scopes = match repo.scopes().await {
			Ok(scopes) => scopes,
			Err(e) => {
				tracing::error!(error = %e, "scope registry unreadable; keeping the previous sign-in allowlist");
				return false;
			}
		};
		if key_of(&scopes) == self.current().key {
			return false;
		}
		match snapshot(&self.public_origin, &scopes) {
			Ok(next) => {
				*self.current.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(next);
				tracing::info!(scopes = scopes.len(), "sign-in allowlist rebuilt from the scope registry");
				true
			}
			Err(e) => {
				tracing::error!(error = ?e, "sign-in allowlist not rebuilt; keeping the previous one");
				false
			}
		}
	}
}

pub async fn run_refresh(allowlist: Arc<SignInAllowlist>, every: Duration) {
	let mut ticks = tokio::time::interval(every);
	// A tick missed while a read was slow is not owed: one fresh read covers them all.
	ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		ticks.tick().await;
		allowlist.refresh().await;
	}
}

/// `https://host[:port]` → `host`.
fn host_of(origin: &str) -> Option<&str> {
	let (_, authority) = origin.split_once("://")?;
	authority.split([':', '/']).next().filter(|host| !host.is_empty())
}

fn key_of(scopes: &[ScopeRecord]) -> Vec<(String, u64)> {
	scopes.iter().map(|s| (s.id.clone(), s.version)).collect()
}

fn snapshot(public_origin: &str, scopes: &[ScopeRecord]) -> Result<Snapshot> {
	let origins = ScopeOrigins::from_scopes(scopes);
	let webauthn = Arc::new(passkey::verifier(public_origin, origins.origins())?);
	Ok(Snapshot {
		origins,
		webauthn,
		key: key_of(scopes),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::web::origins::ScopeOrigins;

	#[test]
	fn a_turnstile_host_is_the_public_origins_or_nothing_else_here() {
		let allowlist = SignInAllowlist::fixed("https://evinvest.ltd", ScopeOrigins::none()).unwrap();
		assert!(allowlist.admits_host("evinvest.ltd"));
		for host in ["evil.example", "invest.evinvest.ltd", "evinvest.ltd.evil.example", ""] {
			assert!(!allowlist.admits_host(host), "{host:?}");
		}
		assert_eq!(host_of("http://localhost:58843"), Some("localhost"));
		assert_eq!(host_of("https://invest.evinvest.ltd"), Some("invest.evinvest.ltd"));
	}
}
