//! The live sign-in allowlist: the scope origins the sign-in routes, the passkey verifier,
//! OAuth `returnTo` and the MFE bundles answer, re-read from the registry at most
//! [`REFRESH_EVERY`] apart.
//!
//! Live and not a boot snapshot, because the answer must follow the registry: a scope
//! that is CLOSED, or an origin that is removed, has to stop being let in without anyone
//! restarting the plane. Cached and not read per request, because preflights are hot and
//! the answer changes on the scale of migrations.

use std::{
	sync::{Arc, RwLock},
	time::{Duration, Instant},
};

use color_eyre::eyre::{Context, Result};
use webauthn_rs::Webauthn;

use crate::{
	ports::ScopeRepository,
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
}

pub struct SignInAllowlist {
	public_origin: String,
	/// `None` ⇒ a fixed allowlist that never refreshes (tests, a plane with no registry).
	source: Option<Arc<dyn ScopeRepository>>,
	ttl: Duration,
	current: RwLock<(Instant, Arc<Snapshot>)>,
	/// One refresh at a time: the others keep answering from the snapshot they have.
	refreshing: tokio::sync::Mutex<()>,
}

impl SignInAllowlist {
	/// Read the registry now — a plane that cannot read it at boot does not start — and
	/// again whenever the reading is older than `ttl`.
	pub async fn live(repo: Arc<dyn ScopeRepository>, public_origin: &str, ttl: Duration) -> Result<Self> {
		let scopes = repo.scopes().await.context("failed to read the scope registry")?;
		let snapshot = snapshot(public_origin, ScopeOrigins::from_scopes(&scopes))?;
		Ok(Self::new(public_origin, Some(repo), ttl, snapshot))
	}

	/// An allowlist that never changes.
	pub fn fixed(public_origin: &str, origins: ScopeOrigins) -> Result<Self> {
		let snapshot = snapshot(public_origin, origins)?;
		Ok(Self::new(public_origin, None, Duration::ZERO, snapshot))
	}

	fn new(public_origin: &str, source: Option<Arc<dyn ScopeRepository>>, ttl: Duration, snapshot: Snapshot) -> Self {
		Self {
			public_origin: public_origin.trim_end_matches('/').to_owned(),
			source,
			ttl,
			current: RwLock::new((Instant::now(), Arc::new(snapshot))),
			refreshing: tokio::sync::Mutex::new(()),
		}
	}

	/// The current reading, refreshed first when it is due. A failed refresh keeps the
	/// previous reading — an outage of the registry must not sign everyone out of every
	/// scope host — and is retried a `ttl` later.
	pub async fn current(&self) -> Arc<Snapshot> {
		let Some(repo) = &self.source else {
			return self.read().1;
		};
		let (taken, previous) = self.read();
		if taken.elapsed() < self.ttl {
			return previous;
		}
		let _refresh = self.refreshing.lock().await;
		let (taken, previous) = self.read();
		if taken.elapsed() < self.ttl {
			return previous;
		}
		let next = match repo.scopes().await {
			Ok(scopes) => match snapshot(&self.public_origin, ScopeOrigins::from_scopes(&scopes)) {
				Ok(next) => Arc::new(next),
				Err(e) => {
					tracing::error!(error = ?e, "sign-in allowlist not rebuilt; keeping the previous one");
					previous
				}
			},
			Err(e) => {
				tracing::error!(error = %e, "scope registry unreadable; keeping the previous sign-in allowlist");
				previous
			}
		};
		*self.current.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = (Instant::now(), next.clone());
		next
	}

	/// Whether a sign-in route may be called from `origin`: this plane's own, or a host of
	/// a scope that signs people in.
	pub async fn admits(&self, origin: &str) -> bool {
		origin == self.public_origin || self.current().await.origins.admits(origin)
	}

	fn read(&self) -> (Instant, Arc<Snapshot>) {
		// A panic while holding the lock leaves a whole value behind (it is replaced in
		// one assignment), so a poisoned lock is still a good reading.
		let guard = self.current.read().unwrap_or_else(|poisoned| poisoned.into_inner());
		(guard.0, guard.1.clone())
	}
}

fn snapshot(public_origin: &str, origins: ScopeOrigins) -> Result<Snapshot> {
	let webauthn = Arc::new(passkey::verifier(public_origin, origins.origins())?);
	Ok(Snapshot { origins, webauthn })
}
