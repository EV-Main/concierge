//! The web session locker: opaque cookie id → the server-held concierge token
//! pair. The refresh token never reaches the browser; the access JWT does (as the
//! zone-shared `ev_access` cookie) but is re-minted here on demand. Ported from
//! the cabinet BFF's session store, trimmed to the identity plane; refresh goes
//! through the issuance service IN-PROCESS rather than over gRPC.
//!
//! Storage mirrors the issuance side's `RefreshStore`: `REDIS_URL` set ⇒ one hash
//! per session in the central Redis, reaped by `EXPIREAT`, surviving restarts and
//! shared across replicas; unset ⇒ an in-process map (local/CI unaffected).
//!
//! The stored `user` summary is a login-time COPY, not the truth: every
//! [`WebSessions::fresh`] re-reads the principal from the directory (through
//! [`PrincipalSource`]) so a role granted from the console shows up on the next
//! `/auth/session`, not after the next refresh rotation (up to the access TTL later).

use std::{collections::HashMap, future::Future};

use color_eyre::eyre::{Context, bail};
use evconcierge_auth::{AuthError, AuthService};
use evconcierge_contracts::concierge::v1::{RefreshRequest, TokenResponse, UserSummary, auth_service_server::AuthService as AuthRpc};
use prost::Message;
use tokio::sync::Mutex;
use tonic::{Code, Request};

use crate::web::{now_secs, random_token, single_flight::KeyedLocks};

/// Refresh the access token when it has less than this long to live, so a token
/// handed to a zone stays valid for the request that follows.
const ACCESS_SKEW_SECS: i64 = 30;

const FIELDS: [&str; 6] = ["access_token", "access_expires_at", "refresh_token", "refresh_expires_at", "csrf", "user"];
#[derive(Clone)]
pub struct WebSession {
	pub access_token: String,
	pub access_expires_at: i64,
	pub refresh_token: String,
	pub refresh_expires_at: i64,
	pub user: UserSummary,
	pub csrf: String,
}

/// The live principal read behind [`WebSessions::fresh`]: the user's CURRENT directory
/// summary, as opposed to the copy the session stored at login. A seam (rather than
/// [`AuthService`] itself) so the locker's tests can answer it without a directory.
pub trait PrincipalSource {
	fn principal(&self, user_id: &str) -> impl Future<Output = Result<UserSummary, AuthError>> + Send;
}

impl PrincipalSource for AuthService {
	async fn principal(&self, user_id: &str) -> Result<UserSummary, AuthError> {
		AuthService::principal(self, user_id).await
	}
}

/// A fresh view of a live session, for the session route and the access cookie.
pub struct Fresh {
	pub user: UserSummary,
	pub access_token: String,
	pub remaining_secs: i64,
}

/// A session whose `auth_time` just moved: what the route sets in the browser.
pub struct Reauthed {
	pub access_token: String,
	pub auth_time: u64,
	pub remaining_secs: i64,
}

pub struct WebSessions {
	store: Store,
	/// The confirmation trips of `/auth/authorize` when there is no Redis: key → (started
	/// at, expires at). With Redis they live there, so any replica can end a trip.
	trips: Mutex<HashMap<String, (i64, i64)>>,
	/// Per-session single-flight for the refresh path: two racing rotations of one
	/// refresh token read as theft upstream and revoke the family. In-process — see
	/// `single_flight` for the one-replica caveat.
	locks: KeyedLocks<String>,
}

impl WebSessions {
	/// Back the store with Redis when `REDIS_URL` is set; otherwise keep the
	/// in-process map (matches `RefreshStore::from_env` one module over).
	pub async fn from_env() -> color_eyre::Result<Self> {
		let store = match std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) {
			Some(url) => {
				let client = redis::Client::open(url.as_str()).context("invalid REDIS_URL")?;
				Store::Redis(client.get_connection_manager().await.context("web session store: redis connect")?)
			}
			None => Store::InProcess(Mutex::new(HashMap::new())),
		};
		Ok(Self {
			store,
			trips: Mutex::new(HashMap::new()),
			locks: KeyedLocks::default(),
		})
	}

	/// Remember that `/auth/authorize` sent this browser to confirm, at `started_at`, for
	/// `ttl_secs`. `key` names the session, the client and the request; a second start
	/// under it restarts the trip.
	pub async fn start_trip(&self, key: &str, started_at: i64, ttl_secs: u64) -> color_eyre::Result<()> {
		match &self.store {
			Store::InProcess(_) => {
				let mut trips = self.trips.lock().await;
				let now = now_secs();
				trips.retain(|_, (_, expires)| *expires > now);
				trips.insert(key.to_owned(), (started_at, now.saturating_add_unsigned(ttl_secs)));
			}
			Store::Redis(conn) => {
				let mut conn = conn.clone();
				let () = redis::cmd("SET")
					.arg(Self::trip_key(key))
					.arg(started_at)
					.arg("EX")
					.arg(ttl_secs)
					.query_async(&mut conn)
					.await
					.context("confirmation trip start")?;
			}
		}
		Ok(())
	}

	/// The start of the trip under `key`, ending it: a trip is taken once, so coming back
	/// twice is a new request. GET and DEL in one script, not `GETDEL`, which older Redis
	/// servers do not have.
	pub async fn take_trip(&self, key: &str) -> color_eyre::Result<Option<i64>> {
		match &self.store {
			Store::InProcess(_) => {
				let now = now_secs();
				Ok(self.trips.lock().await.remove(key).filter(|(_, expires)| *expires > now).map(|(started, _)| started))
			}
			Store::Redis(conn) => {
				let mut conn = conn.clone();
				let script = redis::Script::new("local v = redis.call('GET', KEYS[1]) if v then redis.call('DEL', KEYS[1]) end return v");
				let started: Option<i64> = script.key(Self::trip_key(key)).invoke_async(&mut conn).await.context("confirmation trip take")?;
				Ok(started)
			}
		}
	}

	fn trip_key(key: &str) -> String {
		format!("rpconfirm:{key}")
	}

	/// Open a session for a freshly exchanged token pair. Returns
	/// `(session_id, csrf, max_age_secs)`; `None` when the response carries no user
	/// (an issuance bug — fail the login rather than store a half-session).
	pub async fn put(&self, tokens: TokenResponse) -> color_eyre::Result<Option<(String, String, i64)>> {
		let Some(user) = tokens.user else { return Ok(None) };
		let id = random_token(32);
		let csrf = random_token(32);
		let max_age = (tokens.refresh_expires_at - now_secs()).max(0);
		let session = WebSession {
			access_token: tokens.access_token,
			access_expires_at: tokens.access_expires_at,
			refresh_token: tokens.refresh_token,
			refresh_expires_at: tokens.refresh_expires_at,
			user,
			csrf: csrf.clone(),
		};
		self.store.save(&id, &session).await?;
		Ok(Some((id, csrf, max_age)))
	}

	/// The session's current view, refreshing the access token through the issuance
	/// service when it is about to expire. `Ok(None)` ⇒ the session is gone (expired,
	/// revoked upstream, or never existed) and its cookies should be cleared; `Err` ⇒
	/// the store itself failed and the session's fate is UNKNOWN — don't touch cookies.
	///
	/// The returned `user` is LIVE: re-read from the directory on every call (once — a
	/// refresh in the same call already carries it) and written back so the stored copy
	/// tracks it. A directory failure keeps the stored copy: an outage there must never
	/// sign anyone out or hide a console they hold.
	pub async fn fresh(&self, id: &str, auth: &(impl AuthRpc + PrincipalSource)) -> color_eyre::Result<Option<Fresh>> {
		let _flight = self.locks.acquire(id.to_string()).await;
		let Some(mut s) = self.store.load(id).await? else { return Ok(None) };
		let now = now_secs();
		let mut user_is_live = false;

		if s.access_expires_at <= now + ACCESS_SKEW_SECS {
			if s.refresh_expires_at <= now {
				self.store.remove(id).await?;
				return Ok(None);
			}
			match auth
				.refresh(Request::new(RefreshRequest {
					refresh_token: s.refresh_token.clone(),
				}))
				.await
			{
				Ok(response) => {
					let t = response.into_inner();
					s.access_token = t.access_token;
					s.access_expires_at = t.access_expires_at;
					s.refresh_token = t.refresh_token;
					s.refresh_expires_at = t.refresh_expires_at;
					if let Some(user) = t.user {
						s.user = user;
						user_is_live = true;
					}
					self.store.save(id, &s).await?;
				}
				// An auth verdict kills the session; a transport blip keeps it (the
				// possibly-stale access token is still the best available answer).
				Err(status) if matches!(status.code(), Code::Unauthenticated | Code::PermissionDenied) => {
					self.store.remove(id).await?;
					return Ok(None);
				}
				Err(_) => {}
			}
		}

		if !user_is_live {
			match auth.principal(&s.user.user_id).await {
				// Taken as DATA, whatever it says: a summary that has turned `disabled`
				// is not a verdict on the session here. Ending it stays the refresh path's
				// job (`AuthService::refresh` revokes the family) — a second place deciding
				// when a session dies would be a second place to disagree with the first.
				Ok(user) =>
					if user != s.user {
						s.user = user;
						self.store.save(id, &s).await?;
					},
				Err(err) => {
					tracing::warn!(error = %err, user_id = %s.user.user_id, "web session: live principal read failed; serving the stored summary");
				}
			}
		}

		Ok(Some(Fresh {
			user: s.user,
			access_token: s.access_token,
			remaining_secs: (s.refresh_expires_at - now).max(0),
		}))
	}

	/// Move the session's `auth_time` after a re-authentication the caller has already
	/// decided, and keep the new access token the issuance service minted for it. The
	/// whole step runs under the session's single-flight: the refresh handle is read and
	/// used with no rotation able to land in between (a rotated-out handle would be
	/// refused), and a concurrent [`Self::fresh`] cannot save its older access token over
	/// the new one. The inner `Err` is the issuance service's verdict, or `Unauthenticated` when
	/// the session is gone or is not `user_id`'s.
	pub async fn reauthenticated(&self, id: &str, user_id: &str, auth: &AuthService) -> color_eyre::Result<Result<Reauthed, tonic::Status>> {
		let _flight = self.locks.acquire(id.to_string()).await;
		let mut tried: Option<String> = None;
		loop {
			let Some(s) = self.store.load(id).await? else {
				return Ok(Err(tonic::Status::unauthenticated("no such session")));
			};
			if s.user.user_id != user_id {
				return Ok(Err(tonic::Status::unauthenticated("no such session")));
			}
			let moved = match auth.reauthenticate(&s.refresh_token, user_id).await {
				Ok(moved) => moved,
				// Another replica may have rotated the handle since the load; read the
				// session once more and go again, but only if it holds a different handle.
				Err(status) if status.code() == tonic::Code::Unauthenticated && tried.is_none() => {
					tried = Some(s.refresh_token);
					continue;
				}
				Err(status) => return Ok(Err(status)),
			};
			// Only the access half is written: a whole-session save here would put back the
			// refresh pair this method loaded, over one a rotation elsewhere has since stored.
			if !self.store.set_access(id, &moved.access_token, moved.access_expires_at).await? {
				return Ok(Err(tonic::Status::unauthenticated("no such session")));
			}
			return Ok(Ok(Reauthed {
				access_token: moved.access_token,
				auth_time: moved.auth_time,
				remaining_secs: (s.refresh_expires_at - now_secs()).max(0),
			}));
		}
	}

	/// The session's CSRF token (double-submit check).
	pub async fn csrf(&self, id: &str) -> color_eyre::Result<Option<String>> {
		Ok(self.store.load(id).await?.map(|s| s.csrf))
	}

	/// The session's refresh token (proves identity on ListSessions/RevokeSession).
	pub async fn refresh_token(&self, id: &str) -> color_eyre::Result<Option<String>> {
		Ok(self.store.load(id).await?.map(|s| s.refresh_token))
	}

	/// Drop the session, returning its refresh token for upstream revocation. Waits
	/// out an in-flight [`Self::fresh`]: otherwise its save re-creates the session
	/// after this delete, and the token returned here is the one that refresh just
	/// rotated away from.
	pub async fn forget(&self, id: &str) -> color_eyre::Result<Option<String>> {
		let _flight = self.locks.acquire(id.to_string()).await;
		self.store.remove(id).await
	}
}

enum Store {
	InProcess(Mutex<HashMap<String, WebSession>>),
	Redis(redis::aio::ConnectionManager),
}

/// One `HMGET` reply over [`FIELDS`], in that order. Redis answers a miss with a NIL
/// per field rather than an error, so every element is optional and "all NIL" is the
/// only legitimate absence — anything between that and "all present" is a torn hash.
type SessionFields = (Option<String>, Option<i64>, Option<String>, Option<i64>, Option<String>, Option<Vec<u8>>);

impl Store {
	fn key(id: &str) -> String {
		format!("websess:{id}")
	}

	async fn load(&self, id: &str) -> color_eyre::Result<Option<WebSession>> {
		match self {
			Self::InProcess(map) => Ok(map.lock().await.get(id).cloned()),
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				let fields: SessionFields = redis::cmd("HMGET").arg(Self::key(id)).arg(&FIELDS).query_async(&mut conn).await.context("web session load")?;
				match fields {
					(None, None, None, None, None, None) => Ok(None),
					(Some(access_token), Some(access_expires_at), Some(refresh_token), Some(refresh_expires_at), Some(csrf), Some(user)) => Ok(Some(WebSession {
						access_token,
						access_expires_at,
						refresh_token,
						refresh_expires_at,
						user: UserSummary::decode(user.as_slice()).context("web session user decode")?,
						csrf,
					})),
					_ => bail!("web session {id}: partial hash — store corrupted"),
				}
			}
		}
	}

	async fn save(&self, id: &str, s: &WebSession) -> color_eyre::Result<()> {
		match self {
			Self::InProcess(map) => {
				let now = now_secs();
				let mut map = map.lock().await;
				map.retain(|_, s| s.refresh_expires_at > now);
				map.insert(id.to_string(), s.clone());
			}
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				redis::pipe()
					.atomic()
					.cmd("HSET")
					.arg(Self::key(id))
					.arg(FIELDS[0])
					.arg(&s.access_token)
					.arg(FIELDS[1])
					.arg(s.access_expires_at)
					.arg(FIELDS[2])
					.arg(&s.refresh_token)
					.arg(FIELDS[3])
					.arg(s.refresh_expires_at)
					.arg(FIELDS[4])
					.arg(&s.csrf)
					.arg(FIELDS[5])
					.arg(s.user.encode_to_vec())
					// Reap the session with its refresh window: past it, `fresh` would
					// remove it anyway (mirrors the in-process retain above).
					.expire_at(Self::key(id), s.refresh_expires_at)
					.exec_async(&mut conn)
					.await
					.context("web session save")?;
			}
		}
		Ok(())
	}

	/// Replace the access token alone. `false` when the session is gone: nothing is written
	/// then (a bare `HSET` would conjure a half-hash that `load` reports as corrupted).
	async fn set_access(&self, id: &str, access_token: &str, access_expires_at: i64) -> color_eyre::Result<bool> {
		match self {
			Self::InProcess(map) => Ok(map
				.lock()
				.await
				.get_mut(id)
				.map(|s| {
					s.access_token = access_token.to_owned();
					s.access_expires_at = access_expires_at;
				})
				.is_some()),
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				let script =
					redis::Script::new("if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end redis.call('HSET', KEYS[1], 'access_token', ARGV[1], 'access_expires_at', ARGV[2]) return 1");
				let written: i64 = script
					.key(Self::key(id))
					.arg(access_token)
					.arg(access_expires_at)
					.invoke_async(&mut conn)
					.await
					.context("web session set access")?;
				Ok(written == 1)
			}
		}
	}

	async fn remove(&self, id: &str) -> color_eyre::Result<Option<String>> {
		match self {
			Self::InProcess(map) => Ok(map.lock().await.remove(id).map(|s| s.refresh_token)),
			Self::Redis(conn) => {
				let mut conn = conn.clone();
				let (refresh_token, _deleted): (Option<String>, i64) = redis::pipe()
					.atomic()
					.hget(Self::key(id), "refresh_token")
					.del(Self::key(id))
					.query_async(&mut conn)
					.await
					.context("web session remove")?;
				Ok(refresh_token)
			}
		}
	}
}
