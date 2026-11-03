//! The web-session locker's invariants:
//!
//! - persistence: with `REDIS_URL` set, a session opened by one `WebSessions`
//!   instance is served by a NEW instance — a concierge restart no longer signs
//!   everyone out;
//! - liveness of the principal: `fresh` answers with the directory's CURRENT
//!   summary (a role granted since login shows at once), and a directory outage
//!   falls back to the stored copy rather than ending the session;
//! - a rotation whose answer is lost (the view dropped, its lease lost) does not
//!   sign anyone out: the next view replays it rather than presenting a spent token.

mod common;

use std::sync::Mutex;

use concierge::web::{Issuer, WebSessions};
use evconcierge_auth::{AuthError, AuthService};
use evconcierge_contracts::concierge::v1::{TokenResponse, UserSummary};
use tonic::Status;

fn summary(user_id: &str, role: &str) -> UserSummary {
	UserSummary {
		user_id: user_id.into(),
		email: "user@test".into(),
		status: "active".into(),
		token_version: 1,
		role: role.into(),
		role_is_break_glass: false,
		email_verified: true,
		username: String::new(),
	}
}

fn tokens(user_id: &str) -> TokenResponse {
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
	TokenResponse {
		access_token: "access".into(),
		access_expires_at: now + 900,
		refresh_token: "family.secret".into(),
		refresh_expires_at: now + 3600,
		user: Some(summary(user_id, "investor")),
	}
}

/// A directory stand-in for the live principal read: `Some` answers with that
/// summary, `None` fails as an outage. Issuance is never reached (the access token
/// is far from expiry), so a refresh is a panic — reaching one is a test bug.
struct Directory(Mutex<Option<UserSummary>>);

impl Directory {
	fn answering(user: UserSummary) -> Self {
		Self(Mutex::new(Some(user)))
	}

	fn down() -> Self {
		Self(Mutex::new(None))
	}

	fn set(&self, answer: Option<UserSummary>) {
		*self.0.lock().unwrap() = answer;
	}
}

impl Issuer for Directory {
	async fn principal(&self, _user_id: &str) -> Result<UserSummary, AuthError> {
		self.0.lock().unwrap().clone().ok_or(AuthError::Unavailable)
	}

	async fn refresh_to(&self, _: &str, _: &str) -> Result<TokenResponse, Status> {
		unreachable!("issuance is not part of a live principal read")
	}
}

// A role granted from the console after login is what `/auth/session` reports on
// the very next call — and it is written back, so the stored copy is the new one
// even once the directory can no longer be asked.
#[tokio::test]
async fn fresh_reports_the_directory_role_not_the_login_copy() {
	let sessions = WebSessions::from_env().await.unwrap();
	let (id, ..) = sessions.put(tokens("web-sess-live-role-user")).await.unwrap().expect("token pair carries a user");

	let directory = Directory::answering(summary("web-sess-live-role-user", "operator"));
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("session is live");
	assert_eq!(fresh.user.role, "operator");

	directory.set(None);
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("an outage keeps the session");
	assert_eq!(fresh.user.role, "operator", "the live summary must have been persisted, not only returned");
}

// A directory outage is not a verdict on the session: the login-time copy answers
// and nothing is removed.
#[tokio::test]
async fn fresh_falls_back_to_the_stored_summary_when_the_directory_is_down() {
	let sessions = WebSessions::from_env().await.unwrap();
	let (id, csrf, _) = sessions.put(tokens("web-sess-outage-user")).await.unwrap().expect("token pair carries a user");

	let directory = Directory::down();
	let fresh = sessions.fresh(&id, &directory).await.unwrap().expect("an outage keeps the session");
	assert_eq!(fresh.user.role, "investor");
	assert_eq!(sessions.csrf(&id).await.unwrap(), Some(csrf));

	sessions.forget(&id, &directory).await.unwrap();
}

/// Issuance stand-in whose refresh is slow and rotates the token, to hold `fresh`
/// in flight while the reader signs out.
struct SlowRefresh;

impl Issuer for SlowRefresh {
	async fn principal(&self, _user_id: &str) -> Result<UserSummary, AuthError> {
		unreachable!("a refresh response already carries the live user")
	}

	async fn refresh_to(&self, _: &str, _: &str) -> Result<TokenResponse, Status> {
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
		let mut t = tokens("web-sess-signout-race-user");
		t.refresh_token = "family.rotated".into();
		Ok(t)
	}
}

// Signing out while a refresh is in flight must neither resurrect the session nor
// revoke upstream with the token that refresh just rotated away from.
#[tokio::test]
async fn forget_waits_for_an_inflight_refresh_and_ends_the_session() {
	let sessions = WebSessions::from_env().await.unwrap();
	let mut expiring = tokens("web-sess-signout-race-user");
	expiring.access_expires_at = 0;
	let (id, ..) = sessions.put(expiring).await.unwrap().expect("token pair carries a user");

	let refreshing = sessions.fresh(&id, &SlowRefresh);
	let signing_out = async {
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
		sessions.forget(&id, &SlowRefresh).await.unwrap()
	};
	let (fresh, forgotten) = tokio::join!(refreshing, signing_out);

	assert!(fresh.unwrap().is_some(), "the refresh was already in flight and completes");
	assert_eq!(forgotten.as_deref(), Some("family.rotated"), "upstream must be told the CURRENT token");
	assert!(sessions.fresh(&id, &SlowRefresh).await.unwrap().is_none(), "the session must be dead after sign-out");
}

#[tokio::test]
async fn sessions_survive_a_restart() {
	if std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()).is_none() {
		eprintln!("skipped: REDIS_URL unset — the in-process arm is restart-lossy by design");
		return;
	}

	let before = WebSessions::from_env().await.unwrap();
	let (id, csrf, _max_age) = before.put(tokens("web-sess-restart-user")).await.unwrap().expect("token pair carries a user");
	drop(before);

	// A new instance = a restarted process. The auth service is never consulted
	// while the access token is far from expiry, so the inert one suffices.
	let after = WebSessions::from_env().await.unwrap();
	let auth = AuthService::unconfigured();
	let fresh = after.fresh(&id, &auth).await.unwrap().expect("session must survive the restart");
	assert_eq!(fresh.user.user_id, "web-sess-restart-user");
	assert_eq!(after.csrf(&id).await.unwrap(), Some(csrf));

	// forget hands back the refresh token for upstream revocation and ends the session.
	assert_eq!(after.forget(&id, &auth).await.unwrap().as_deref(), Some("family.secret"));
	assert!(after.fresh(&id, &auth).await.unwrap().is_none());
}

/// Issuance stand-in that spends what it rotates, as the real one does: a refresh token
/// presented twice is the theft upstream revokes a family for. `hold` keeps a rotation in
/// flight; `None` never answers, as a holder that died mid-call.
struct Rotating {
	hold: Option<std::time::Duration>,
	in_flight: std::sync::atomic::AtomicBool,
	spent: Mutex<Vec<String>>,
}

impl Rotating {
	fn holding(hold: std::time::Duration) -> Self {
		Self {
			hold: Some(hold),
			in_flight: Default::default(),
			spent: Mutex::default(),
		}
	}

	fn hanging() -> Self {
		Self {
			hold: None,
			in_flight: Default::default(),
			spent: Mutex::default(),
		}
	}
}

impl Issuer for Rotating {
	async fn principal(&self, user_id: &str) -> Result<UserSummary, AuthError> {
		Ok(summary(user_id, "investor"))
	}

	async fn refresh_to(&self, presented: &str, _: &str) -> Result<TokenResponse, Status> {
		use std::sync::atomic::Ordering;
		assert!(!self.in_flight.swap(true, Ordering::SeqCst), "two rotations of one session in flight at once");
		{
			let mut spent = self.spent.lock().unwrap();
			assert!(!spent.iter().any(|s| s == presented), "{presented} rotated twice: upstream revokes the family");
			spent.push(presented.to_owned());
		}
		match self.hold {
			Some(hold) => tokio::time::sleep(hold).await,
			None => std::future::pending().await,
		}
		self.in_flight.store(false, Ordering::SeqCst);
		let mut t = tokens("web-sess-flight-user");
		t.refresh_token = format!("{presented}.next");
		Ok(t)
	}
}

/// Two `WebSessions` over one Redis stand for two concierge processes.
async fn two_processes() -> Option<(WebSessions, WebSessions)> {
	if std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()).is_none() {
		eprintln!("skipped: REDIS_URL unset — without a shared store there is one process by construction");
		return None;
	}
	Some((WebSessions::from_env().await.unwrap(), WebSessions::from_env().await.unwrap()))
}

// Two processes refreshing one session at once rotate it once: the second serves the
// pair the first stored, even while that rotation outlives a lease's unrenewed TTL.
#[tokio::test]
async fn two_processes_rotate_a_session_once() {
	let Some((a, b)) = two_processes().await else { return };
	let mut expiring = tokens("web-sess-flight-user");
	expiring.access_expires_at = 0;
	let (id, ..) = a.put(expiring).await.unwrap().expect("token pair carries a user");

	let upstream = Rotating::holding(std::time::Duration::from_secs(6));
	let (first, second) = tokio::join!(a.fresh(&id, &upstream), b.fresh(&id, &upstream));

	assert!(first.unwrap().is_some() && second.unwrap().is_some(), "both reads serve the session");
	assert_eq!(*upstream.spent.lock().unwrap(), ["family.secret"]);
	assert_eq!(b.forget(&id, &upstream).await.unwrap().as_deref(), Some("family.secret.next"));
}

// A process that dies holding a session's turn stalls the others only until its lease
// lapses.
#[tokio::test]
async fn a_dead_holders_turn_lapses() {
	let Some((a, b)) = two_processes().await else { return };
	let mut expiring = tokens("web-sess-flight-user");
	expiring.access_expires_at = 0;
	let (id, ..) = a.put(expiring).await.unwrap().expect("token pair carries a user");

	let hung = Rotating::hanging();
	assert!(
		tokio::time::timeout(std::time::Duration::from_millis(300), a.fresh(&id, &hung)).await.is_err(),
		"the hung rotation holds the turn"
	);
	drop(a);

	let started = std::time::Instant::now();
	let upstream = Rotating::holding(std::time::Duration::ZERO);
	let fresh = b.fresh(&id, &upstream).await.unwrap();
	assert!(fresh.is_some(), "the turn comes back once the lease lapses");
	assert!(started.elapsed() > std::time::Duration::from_secs(1), "went in while the dead holder's lease was live");
	b.forget(&id, &upstream).await.unwrap();
}

/// The directory behind a real issuer: every lookup is `user_id`, active.
async fn directory(mut rx: tokio::sync::mpsc::Receiver<evconcierge_auth::ProvisionRequest>, user_id: &str) -> std::convert::Infallible {
	while let Some(request) = rx.recv().await {
		let user = evconcierge_auth::ProvisionedUser {
			user_id: user_id.into(),
			email: "user@test".into(),
			email_verified: true,
			username: String::new(),
			status: "active".into(),
			token_version: 1,
			role: "investor".into(),
			role_is_break_glass: false,
		};
		request.respond_to.send(Ok(user)).expect("the issuer awaits its lookup");
	}
	unreachable!("the issuer holds the sender")
}

/// A session whose access token is due, over a family the real issuer opened.
async fn due_session(auth: &AuthService, sessions: &WebSessions, user_id: &str) -> String {
	let mut pair = tokens(user_id);
	pair.access_expires_at = 0;
	pair.refresh_token = auth.open_family_for_tests(user_id, 1).await.unwrap();
	sessions.put(pair).await.unwrap().expect("token pair carries a user").0
}

/// The real issuer whose answer to a rotation does not come back: held for `hold`, or
/// never (`None`), after the rotation landed upstream.
struct Losing {
	auth: AuthService,
	hold: Option<std::time::Duration>,
	rotated: std::sync::atomic::AtomicBool,
}

impl Losing {
	fn new(auth: &AuthService, hold: Option<std::time::Duration>) -> Self {
		Self {
			auth: auth.clone(),
			hold,
			rotated: Default::default(),
		}
	}

	fn rotated(&self) -> bool {
		self.rotated.load(std::sync::atomic::Ordering::SeqCst)
	}
}

impl Issuer for Losing {
	async fn principal(&self, user_id: &str) -> Result<UserSummary, AuthError> {
		self.auth.principal(user_id).await
	}

	async fn refresh_to(&self, refresh_token: &str, next_secret: &str) -> Result<TokenResponse, Status> {
		let answer = self.auth.refresh_to(refresh_token, next_secret).await;
		assert!(answer.is_ok(), "the rotation lands upstream");
		self.rotated.store(true, std::sync::atomic::Ordering::SeqCst);
		match self.hold {
			Some(hold) => tokio::time::sleep(hold).await,
			None => std::future::pending().await,
		}
		answer
	}
}

/// The session survived: the next view serves it and its family is still the live one upstream.
async fn assert_still_signed_in(auth: &AuthService, sessions: &WebSessions, id: &str) {
	assert!(sessions.fresh(id, auth).await.unwrap().is_some(), "the next view must serve the session");
	let refresh = sessions.refresh_token(id).await.unwrap().expect("the session is stored");
	assert!(auth.live_family(&refresh).await.unwrap().is_some(), "the family must not have been revoked as reuse");
}

// A view dropped after its rotation landed upstream (a client gone, a timeout fired)
// must not leave the session holding the spent token.
#[tokio::test]
async fn a_rotation_whose_answer_is_lost_does_not_sign_the_user_out() {
	let user_id = "web-sess-lost-answer-user";
	let (provisioner, rx) = evconcierge_auth::provisioner_channel();
	let auth = common::issuer(provisioner).await;
	tokio::select! {
		never = directory(rx, user_id) => match never {},
		() = async {
			let sessions = WebSessions::from_env().await.unwrap();
			let id = due_session(&auth, &sessions, user_id).await;

			let losing = Losing::new(&auth, None);
			assert!(tokio::time::timeout(std::time::Duration::from_secs(2), sessions.fresh(&id, &losing)).await.is_err(), "the view is dropped mid-flight");
			assert!(losing.rotated(), "dropped after the rotation, not before");

			assert_still_signed_in(&auth, &sessions, &id).await;
		} => {}
	}
}

// The single flight drops a section whose lease it could not keep; a refresh dropped
// there after its rotation must not sign the user out either.
#[tokio::test]
async fn a_section_cancelled_for_its_lost_lease_does_not_sign_the_user_out() {
	let Some(url) = std::env::var("REDIS_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipped: REDIS_URL unset — without Redis the turn is a mutex and no lease can be lost");
		return;
	};
	let user_id = "web-sess-lost-lease-user";
	let (provisioner, rx) = evconcierge_auth::provisioner_channel();
	let auth = common::issuer(provisioner).await;
	tokio::select! {
		never = directory(rx, user_id) => match never {},
		() = async {
			let sessions = WebSessions::from_env().await.unwrap();
			let id = due_session(&auth, &sessions, user_id).await;

			let losing = Losing::new(&auth, Some(std::time::Duration::from_secs(4)));
			let mut redis = redis::Client::open(url.as_str()).unwrap().get_multiplexed_async_connection().await.unwrap();
			let take_the_lease = async {
				tokio::time::sleep(std::time::Duration::from_millis(300)).await;
				let deleted: i64 = redis::cmd("DEL").arg(format!("flight:websess:{id}")).query_async(&mut redis).await.unwrap();
				assert_eq!(deleted, 1, "the view holds its lease");
			};
			let (cancelled, ()) = tokio::join!(sessions.fresh(&id, &losing), take_the_lease);
			assert!(cancelled.is_err(), "a lost lease cancels the section");
			assert!(losing.rotated(), "cancelled after the rotation, not before");

			assert_still_signed_in(&auth, &sessions, &id).await;
		} => {}
	}
}
