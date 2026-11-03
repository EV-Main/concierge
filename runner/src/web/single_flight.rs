//! Per-key single flight: at most one in-flight section per key, across every process
//! sharing `REDIS_URL`.
//!
//! The two callers are the session refresh (two racing rotations of one refresh token
//! read as theft upstream) and `/kyc/start` (two racing starts buy two paid vendor
//! sessions). Both need the same thing — "the second caller waits for the first and then
//! re-reads" — and neither wants a database lock, because what they hold it across is a
//! network round trip.
//!
//! With Redis a key's turn is a lease (`SET NX PX`) renewed while its section runs and
//! released by compare-and-delete; a local mutex in front queues one process's waiters so
//! only the first of them polls Redis. Without Redis the session store is in-process too,
//! so there is one process by construction and the mutex alone is the turn.

use std::{collections::HashMap, fmt::Display, future::Future, hash::Hash, sync::Arc, time::Duration};

use color_eyre::eyre::{Context, bail, eyre};
use redis::aio::ConnectionManager;
use tokio::sync::Mutex;

use crate::web::random_token;

/// Renewed every third of it, each renewal one command under redis-rs's 500 ms response
/// timeout, so it lapses only for a holder that died, was cancelled or lost Redis. No
/// fencing token: what a section guards (a single-use refresh token upstream, a billed
/// vendor call) cannot check one, so exclusion holds unless a process stalls past it.
const LEASE_TTL: Duration = Duration::from_secs(5);
/// Outlasts the longest section that finishes, `/kyc/start`'s vendor call and its two
/// statements, and a dead holder's lease.
const WAIT: Duration = Duration::from_secs(crate::infrastructure::kyc::didit::SESSION_TIMEOUT.as_secs() + 5);
const POLL: Duration = Duration::from_millis(50);

const RENEW: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) end return 0";
const RELEASE: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0";

pub(super) struct KeyedLocks<K> {
	ns: &'static str,
	redis: Option<ConnectionManager>,
	locks: Mutex<HashMap<K, Arc<Mutex<()>>>>,
}

impl<K: Hash + Eq + Display> KeyedLocks<K> {
	/// Leases in Redis when `REDIS_URL` is set, under `flight:<ns>:`.
	pub(super) async fn from_env(ns: &'static str) -> color_eyre::Result<Self> {
		let redis = match std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) {
			Some(url) => Some(
				redis::Client::open(url.as_str())
					.context("invalid REDIS_URL")?
					.get_connection_manager()
					.await
					.context("single flight: redis connect")?,
			),
			None => None,
		};
		Ok(Self {
			ns,
			redis,
			locks: Mutex::new(HashMap::new()),
		})
	}

	/// Run `section` as the key's only one in flight. `Err` when the turn did not come within
	/// [`WAIT`] or Redis failed under it; a section whose lease was lost is dropped
	/// mid-flight rather than finished unexcluded.
	pub(super) async fn run<T>(&self, key: K, section: impl Future<Output = T>) -> color_eyre::Result<T> {
		let ns = self.ns;
		let lease = format!("flight:{ns}:{key}");
		let token = random_token(16);
		let lock = {
			let mut locks = self.locks.lock().await;
			// The owned guard keeps its `Arc` alive, so a count of one means nobody holds
			// or awaits the key — reaping here bounds the map by in-flight keys, not by
			// every key ever seen.
			locks.retain(|_, l| Arc::strong_count(l) > 1);
			locks.entry(key).or_default().clone()
		};
		let _turn = tokio::time::timeout(WAIT, async {
			let turn = lock.lock_owned().await;
			if let Some(conn) = &self.redis {
				let mut conn = conn.clone();
				loop {
					let set: Option<String> = redis::cmd("SET")
						.arg(&lease)
						.arg(&token)
						.arg("NX")
						.arg("PX")
						.arg(LEASE_TTL.as_millis() as u64)
						.query_async(&mut conn)
						.await
						.with_context(|| format!("single flight {ns}: lease"))?;
					if set.is_some() {
						break;
					}
					tokio::time::sleep(POLL).await;
				}
			}
			color_eyre::eyre::Ok(turn)
		})
		.await
		.map_err(|_| eyre!("single flight {ns}: no turn within {WAIT:?}"))??;

		let Some(conn) = &self.redis else { return Ok(section.await) };
		let mut renewing = conn.clone();
		let renew = async {
			loop {
				tokio::time::sleep(LEASE_TTL / 3).await;
				match redis::Script::new(RENEW)
					.key(&lease)
					.arg(&token)
					.arg(LEASE_TTL.as_millis() as u64)
					.invoke_async::<i64>(&mut renewing)
					.await
				{
					Ok(0) => break eyre!("single flight {ns}: lease lost"),
					Ok(_) => {}
					Err(e) => break eyre!(e).wrap_err(format!("single flight {ns}: renew")),
				}
			}
		};
		let out = tokio::select! {
			out = section => out,
			lost = renew => {
				// The dropped section may have rotated upstream without storing what it got.
				tracing::error!(ns, error = ?lost, "single flight: section cancelled, its lease could not be kept");
				return Err(lost);
			}
		};
		let mut conn = conn.clone();
		let released: i64 = redis::Script::new(RELEASE)
			.key(&lease)
			.arg(&token)
			.invoke_async(&mut conn)
			.await
			.with_context(|| format!("single flight {ns}: release"))?;
		if released == 0 {
			bail!("single flight {ns}: lease lapsed under its holder");
		}
		Ok(out)
	}
}
