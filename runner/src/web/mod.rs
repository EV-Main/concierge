//! The site-level auth HTTP surface — the one plain-HTTP seam of the plane.
//!
//! Auth is shell-owned: the site conductor rewrites `evinvest.ltd/api/auth/*` and
//! `/api/callback/auth/*` here, so the browser only ever sees the shared origin and
//! every zone (cabinet, REA, …) receives the same two cookies first-party:
//!
//!   - `__Host-ev_session` — opaque id for the server-held token pair (refresh
//!     rotation stays server-side, never in the browser).
//!   - `__Host-ev_access`  — the short-TTL access JWT, `Path=/`, so a zone's own
//!     backend authenticates a request by verifying it locally against this
//!     plane's JWKS (`evconcierge_auth::Verifier`) — no per-request round trip and
//!     no zone-side OAuth. A zone signs a user in by linking to
//!     `/api/auth/login?returnTo=<path>`; that is the entire zone-side contract.
//!
//! Besides the sessions, it is the account-less notification edge: the subscribe form
//! (`POST /auth/notifications/subscribe`, Turnstile, scope hosts allowed) and the confirm
//! and unsubscribe links every topic mail carries (`/auth/notifications/{confirm,
//! unsubscribe}`, a page on GET, the change on POST) — `web::notifications`.
//!
//! Nothing banking lives here: the money-plane token pair is the cabinet's own concern,
//! minted zone-side from the verified access token.

mod account;
pub mod allowlist;
mod authorize;
mod cors;
mod kyc;
mod logout;
pub mod mfe;
mod notifications;
mod oauth;
pub mod origins;
mod passkey;
mod reauth;
mod routes;
pub mod second_factor;
mod session;
mod sign_in;
mod signup;
mod single_flight;
pub mod stepup;
mod turnstile;

// The one session-store name tests exercise the persistence invariant through.
use std::sync::Arc;

use axum::{
	Router,
	http::Method,
	middleware,
	routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use domain::users::UserId;
use evconcierge_auth::{AuthService, oauth::OAuthProvider};
/// Re-exported so the integration suite asserts against the cap the route actually
/// enforces. A test that hard-coded the number would keep passing after someone raised
/// it, and the number is what stands between one account and the vendor balance.
pub use kyc::START_MAX_PER_WINDOW;
/// Re-exported for the same reason: the suite drives the passkey sign-in up to this budget.
pub use passkey::SIGN_IN_STARTS_PER_MINUTE;
/// Re-exported for the same reason: the suite drives re-authentication up to this budget.
pub use reauth::ATTEMPTS_PER_WINDOW as REAUTH_ATTEMPTS_PER_WINDOW;
pub use session::{PrincipalSource, WebSessions};
use time::Duration;
use tokio::sync::Notify;
pub use turnstile::{SITEVERIFY, Turnstile, is_test_secret};
use webauthn_rs::{
	Webauthn,
	prelude::{DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration},
};

use crate::{
	notification::RateLimiter,
	ports::{CredentialRepository, GovernanceRepository, KycCaseRepository, KycProvider, NotificationRepository, UserDirectoryRepository},
	relying_party::RelyingParties,
	web::{allowlist::SignInAllowlist, oauth::OAuthTxStore, passkey::Ceremonies, single_flight::KeyedLocks},
};

/// Cookie names + shared attributes. `__Host-` prefixed when secure (production);
/// bare in http dev, since the prefix requires `Secure`.
pub struct CookieNames {
	pub session: String,
	pub csrf: String,
	pub access: String,
	pub oauth_tx: String,
	secure: bool,
}
impl CookieNames {
	pub fn new(secure: bool) -> Self {
		let prefix = if secure { "__Host-" } else { "" };
		Self {
			session: format!("{prefix}ev_session"),
			csrf: format!("{prefix}ev_csrf"),
			access: format!("{prefix}ev_access"),
			oauth_tx: format!("{prefix}ev_oauth_tx"),
			secure,
		}
	}

	/// A server-side (HttpOnly) cookie carrying the shared base attributes.
	pub fn server_cookie(&self, name: String, value: String, max_age: i64) -> Cookie<'static> {
		self.build(name, value, max_age, true)
	}

	/// The CSRF cookie — NOT HttpOnly, so client JS can read it for the double-submit header.
	pub fn readable_cookie(&self, name: String, value: String, max_age: i64) -> Cookie<'static> {
		self.build(name, value, max_age, false)
	}

	/// An expiring cookie that clears `name` (empty value, `Max-Age=0`, same attributes).
	pub fn removal(&self, name: String, http_only: bool) -> Cookie<'static> {
		self.build(name, String::new(), 0, http_only)
	}

	fn build(&self, name: String, value: String, max_age: i64, http_only: bool) -> Cookie<'static> {
		let mut c = Cookie::new(name, value);
		c.set_path("/");
		c.set_http_only(http_only);
		c.set_secure(self.secure);
		c.set_same_site(SameSite::Lax);
		c.set_max_age(Duration::seconds(max_age));
		c
	}
}

/// Shared state for the auth HTTP routes. Cheaply cloneable.
#[derive(Clone)]
pub struct WebState {
	inner: Arc<Inner>,
}
impl WebState {
	/// `relying_parties` is `None` where no client flow is mounted; `/auth/authorize` then
	/// answers 503 with a page, never a redirect.
	pub async fn try_new(
		auth: AuthService,
		public_origin: String,
		secure_cookies: bool,
		sign_in: SignInDeps,
		kyc: KycDeps,
		relying_parties: Option<Arc<RelyingParties>>,
	) -> color_eyre::Result<Self> {
		let stepup = sign_in.stepup.map(|deps| stepup::Stepup::new(deps, &public_origin)).transpose()?;
		let second_factor = sign_in.second_factor.map(second_factor::SecondFactor::new);
		Ok(Self {
			inner: Arc::new(Inner {
				auth,
				oauth: OAuthTxStore::new(),
				sessions: WebSessions::from_env().await?,
				cookies: CookieNames::new(secure_cookies),
				providers: sign_in.providers,
				turnstile: sign_in.turnstile,
				credentials: sign_in.credentials,
				mail_wake: sign_in.mail_wake,
				allowlist: sign_in.allowlist,
				passkey_registrations: Ceremonies::default(),
				passkey_sign_ins: Ceremonies::default(),
				passkey_sign_in_starts: RateLimiter::new(std::time::Duration::from_secs(60), passkey::SIGN_IN_STARTS_PER_MINUTE),
				passkey_reauths: Ceremonies::default(),
				reauth_attempts: RateLimiter::new(std::time::Duration::from_secs(reauth::WINDOW_SECS), reauth::ATTEMPTS_PER_WINDOW),
				subscribe_limiter: sign_in.subscribe_limiter,
				stepup,
				second_factor,
				public_origin: public_origin.trim_end_matches('/').to_string(),
				users: kyc.users,
				kyc_cases: kyc.cases,
				kyc_starts: KeyedLocks::default(),
				notifications: kyc.notifications,
				governance: kyc.governance,
				kyc: kyc.provider,
				support_email: kyc.support_email,
				kyc_case_ttl_secs: kyc.case_ttl_secs,
				relying_parties,
			}),
		})
	}
}

/// What the sign-in routes need beyond the session machinery.
pub struct SignInDeps {
	/// The OAuth providers offered, each answering at `/callback/auth/<name>`.
	pub providers: Vec<OAuthProvider>,
	pub turnstile: Turnstile,
	pub credentials: Arc<dyn CredentialRepository>,
	/// The mail dispatcher's wake-up: a queued code leaves now rather than on the next tick.
	pub mail_wake: Arc<Notify>,
	/// The scope hosts the sign-in routes answer besides `PUBLIC_ORIGIN`, and the passkey
	/// verifier built over them — both following the registry.
	pub allowlist: Arc<SignInAllowlist>,
	/// The per-IP budget of the account-less subscribe: the SAME limiter
	/// `NotificationService.SubscribeAnonymous` spends, so the two doors share one budget.
	pub subscribe_limiter: Arc<RateLimiter>,
	/// `None` ⇒ `/auth/stepup/*` is not mounted and answers 404 (`STEPUP_PROOF_ORIGINS`
	/// unset): a host page can ask for nothing.
	pub stepup: Option<stepup::StepupDeps>,
	/// `None` ⇒ `/auth/second-factor/*` is not mounted and answers 404
	/// (`SECOND_FACTOR_SEAL_KEY_FILE` unset): no account can enrol a factor.
	pub second_factor: Option<second_factor::SecondFactorDeps>,
}

/// What the identity-verification routes need, gathered so the composition root hands
/// this surface one argument rather than four.
pub struct KycDeps {
	/// The SAME directory port the operator RPC writes the level through.
	pub users: Arc<dyn UserDirectoryRepository>,
	pub cases: Arc<dyn KycCaseRepository>,
	pub notifications: Arc<dyn NotificationRepository>,
	/// The owner roster and the un-mutable mail queue, for the one verdict that needs a
	/// human and would otherwise reach nobody.
	pub governance: Arc<dyn GovernanceRepository>,
	/// `None` ⇒ the vendor is unconfigured and both KYC routes answer 503. There is no
	/// arm here that verifies nothing: a webhook we cannot authenticate is dropped.
	pub provider: Option<Arc<dyn KycProvider>>,
	/// Printed on the "verification is unavailable" answer, so a user who cannot get
	/// verified has somewhere to go instead of a dead end.
	pub support_email: String,
	/// `KYC_CASE_TTL_SECS` — how long an attempt waiting on the USER counts as running
	/// before both KYC routes treat it as abandoned (#91).
	pub case_ttl_secs: i64,
}

/// The auth surface, mounted behind the conductor's `/api` prefix rewrites:
/// `/api/auth/:rest*` → `/auth/:rest*`, `/api/callback/auth/*` → `/callback/auth/*`.
pub fn router(state: WebState) -> Router {
	// The routes a scope's host may call — closed on purpose (`docs/SCOPES-AND-APPROVALS.md`
	// §3.1). Everything acting on an open session (email verification, password set,
	// passkey register/remove, second factors, sessions, username, methods, `/auth/me`, notification
	// settings, logout, `/kyc/*`) stays off this list: those carry the CSRF double-submit,
	// or read the account, and a script on a scope host must be able to start a sign-in but
	// never act for the account. A scope host proves a mailbox by signing in with a code,
	// or confirms a password sign-up with its ticket (`signup`). The account-less
	// subscribe is on it because it acts for no account: it names an address, which only
	// the confirmation mail it may queue can bind (`web::notifications`).
	//
	// `.layer` on these sub-routers and not `route_layer`: a route layer runs only for a
	// method the route has, so the OPTIONS preflight of a POST route would never reach
	// the CORS layer.
	let allowlist = state.inner.allowlist.clone();
	let scope_posts = Router::new()
		.route("/auth/code/request", post(sign_in::request_code))
		.route("/auth/code/verify", post(sign_in::verify_code))
		.route("/auth/password/signup", post(sign_in::sign_up))
		.route("/auth/password/signin", post(sign_in::sign_in))
		.route("/auth/password/signup/confirm", post(signup::confirm))
		.route("/auth/password/signup/resend", post(signup::resend))
		.route("/auth/passkey/signin/options", post(passkey::signin_options))
		.route("/auth/passkey/signin/verify", post(passkey::signin_verify))
		.route("/auth/notifications/subscribe", post(notifications::subscribe))
		.layer(cors::layer(allowlist.clone(), Method::POST));
	let scope_reads = Router::new().route("/auth/session", get(routes::session)).layer(cors::layer(allowlist, Method::GET));
	// Step-up for a page of a trusted host: mounted only where `STEPUP_PROOF_ORIGINS` names
	// an origin, with its own CORS layer over that exact list and a guard for what a
	// preflight cannot settle (`web::stepup`). `.layer` for the same reason as above: the
	// preflight of a POST route must reach the CORS layer.
	let stepup_posts = match state.inner.stepup.as_ref() {
		Some(stepup) => Router::new()
			.route("/auth/stepup/options", post(stepup::options))
			.route("/auth/stepup/verify", post(stepup::verify))
			.layer(middleware::from_fn_with_state(state.clone(), stepup::guard))
			.layer(stepup.cors()),
		None => Router::new(),
	};
	// The account's second factors: `PUBLIC_ORIGIN` only, CSRF on every one
	// (`web::second_factor`), mounted only where a seal key is configured.
	let second_factor_posts = match state.inner.second_factor {
		Some(_) => Router::new()
			.route("/auth/second-factor/enrol/start", post(second_factor::enrol_start))
			.route("/auth/second-factor/enrol/confirm", post(second_factor::enrol_confirm))
			.route("/auth/second-factor/verify/options", post(second_factor::verify_options))
			.route("/auth/second-factor/verify", post(second_factor::verify))
			.route("/auth/second-factor/remove", post(second_factor::remove))
			.route("/auth/second-factor/recovery-codes", post(second_factor::replace_recovery_codes))
			.route("/auth/second-factor/recover", post(second_factor::recover)),
		None => Router::new(),
	};
	Router::new()
		.merge(scope_posts)
		.merge(scope_reads)
		.merge(stepup_posts)
		.merge(second_factor_posts)
		// k8s liveness/readiness probe target.
		.route("/health", get(|| async { "ok" }))
		.route("/auth/login", get(routes::login))
		.route("/callback/auth/{provider}", get(routes::callback))
		.route("/auth/logout", post(routes::logout))
		// The sign-out a scope's host sends the browser to, so that leaving the scope
		// leaves this origin's session too. A page, not a call: a script on a scope host
		// must never be able to end the session by itself, so a person presses the button.
		.route("/auth/logout/confirm", get(logout::page).post(logout::confirm))
		.route("/auth/sessions", get(routes::list_sessions).delete(routes::revoke_session))
		.route("/auth/email/verify/request", post(sign_in::request_verification))
		.route("/auth/email/verify/confirm", post(sign_in::confirm_verification))
		.route("/auth/password/set", post(sign_in::set_password))
		.route("/auth/username", post(sign_in::set_username))
		.route("/auth/methods", get(sign_in::methods))
		// The account MFE: `PUBLIC_ORIGIN` only, CSRF on every mutation (`web::account`).
		.route("/auth/me", get(account::me))
		.route("/auth/notifications/settings", get(account::notification_settings))
		.route("/auth/notifications/settings/channel", post(account::set_channel))
		.route("/auth/notifications/settings/topic", post(account::set_topic))
		// The links every topic mail carries: a page with a button on GET, the change on
		// POST — and, for unsubscribe, RFC 8058's one-click POST. Authorised by the token
		// alone, so no session, no CSRF, no CORS (`web::notifications`).
		.route("/auth/notifications/confirm", get(notifications::confirm_page).post(notifications::confirm))
		.route("/auth/notifications/unsubscribe", get(notifications::unsubscribe_page).post(notifications::unsubscribe))
		.route("/auth/passkey/register/options", post(passkey::register_options))
		.route("/auth/passkey/register/verify", post(passkey::register_verify))
		.route("/auth/passkey/remove", post(passkey::remove))
		// Re-authentication: prove the signed-in account again and move the session's
		// `auth_time`, without a new session. `PUBLIC_ORIGIN` only (no CORS), CSRF-checked
		// (`web::reauth`).
		.route("/auth/reauth/code/request", post(reauth::code_request))
		.route("/auth/reauth/code/verify", post(reauth::code_verify))
		.route("/auth/reauth/password", post(reauth::password))
		.route("/auth/reauth/passkey/options", post(reauth::passkey_options))
		.route("/auth/reauth/passkey/verify", post(reauth::passkey_verify))
		// The relying-party code flow's front door. It needs no CSRF token: it changes
		// nothing a cross-site request could exploit — it only ever redirects to an
		// address registered for the client, carrying a code that is useless without the
		// PKCE verifier the client kept.
		.route("/auth/authorize", get(authorize::authorize))
		// The name of the app the confirmation page (`authorize::CONFIRM_PATH`) asks for:
		// public and same-origin, read from the registry (`web::authorize::client_name`).
		.route("/auth/clients/{client_id}", get(authorize::client_name))
		// Identity verification. `/kyc/callback/didit` is PUBLIC — it is reached by the
		// vendor, not a browser, and authenticates itself with an HMAC over the body.
		// Publicly both are seen under the conductor's `/api` prefix.
		.route("/kyc/start", post(kyc::start))
		// A read, so no CSRF token and no vendor: the level and the running case are
		// facts of THIS plane, and the cabinet needs them even while Didit is down.
		.route("/kyc/status", get(kyc::status))
		.route("/kyc/callback/didit", post(kyc::callback))
		.with_state(state)
}

/// An opaque identifier: `n` bytes of CSPRNG entropy, base64url-encoded (no padding).
fn random_token(n: usize) -> String {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	let mut buf = vec![0u8; n];
	getrandom::fill(&mut buf).expect("CSPRNG unavailable");
	URL_SAFE_NO_PAD.encode(buf)
}

/// Current unix time in seconds (matches the proto `*_expires_at` fields).
fn now_secs() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

struct Inner {
	/// The issuance service, called IN-PROCESS through its gRPC trait — the web
	/// layer is just another (local) client of the same `Exchange`/`Refresh`/
	/// `Logout` surface, so issuance semantics live in exactly one place.
	auth: AuthService,
	oauth: OAuthTxStore,
	sessions: WebSessions,
	cookies: CookieNames,
	/// An absent provider's login answers 503 (mirrors the inert plane).
	providers: Vec<OAuthProvider>,
	turnstile: Turnstile,
	credentials: Arc<dyn CredentialRepository>,
	mail_wake: Arc<Notify>,
	allowlist: Arc<SignInAllowlist>,
	/// Each ceremony keeps the verifier that began it, so both halves check against one
	/// reading of the allowlist even if it is rebuilt in between.
	passkey_registrations: Ceremonies<(UserId, PasskeyRegistration, Arc<Webauthn>)>,
	passkey_sign_ins: Ceremonies<(DiscoverableAuthentication, Arc<Webauthn>)>,
	/// A re-authentication ceremony is bound to the account that began it.
	passkey_reauths: Ceremonies<(UserId, PasskeyAuthentication, Arc<Webauthn>)>,
	/// Per ACCOUNT (not per address — the caller is signed in): every re-authentication
	/// request spends from it, so a stolen session cannot be used to grind a password,
	/// a code or an assertion any faster than this.
	reauth_attempts: RateLimiter,
	/// Per client address, in process: a replica's own ceremony store is what it protects.
	passkey_sign_in_starts: RateLimiter,
	subscribe_limiter: Arc<RateLimiter>,
	stepup: Option<stepup::Stepup>,
	second_factor: Option<second_factor::SecondFactor>,
	/// The user-facing origin the conductor serves (e.g. `https://evinvest.ltd`).
	/// Builds the redirect_uri: `{public_origin}/api/callback/auth/<provider>`.
	public_origin: String,
	/// The identity control plane — the KYC webhook applies its verdict through the same
	/// port the operator console's `SetKycLevel` does.
	users: Arc<dyn UserDirectoryRepository>,
	kyc_cases: Arc<dyn KycCaseRepository>,
	/// Per-user single-flight for `/kyc/start`: the start gate is a read, and this is
	/// what stops two simultaneous starts from both passing it (#56).
	kyc_starts: KeyedLocks<UserId>,
	notifications: Arc<dyn NotificationRepository>,
	/// Reached for ONE thing: queueing the owners' alert when a verification verdict
	/// contradicts a level an account already holds. That mail must not be switchable
	/// off by its recipient, which is what the governance queue gives and the
	/// subscribable notification topic does not.
	governance: Arc<dyn GovernanceRepository>,
	/// `None` ⇒ unconfigured; both KYC routes answer 503.
	kyc: Option<Arc<dyn KycProvider>>,
	/// Human contact handed to a user whose verification cannot run right now.
	support_email: String,
	/// How long a KYC attempt whose next move is the user's counts as running. Read by
	/// both KYC routes, so `/kyc/status` and `/kyc/start` can never disagree about which
	/// cases are still alive — the disagreement #190 was about, arrived at from the other
	/// end.
	kyc_case_ttl_secs: i64,
	/// The relying-party registry and policy behind `/auth/authorize`.
	relying_parties: Option<Arc<RelyingParties>>,
}
