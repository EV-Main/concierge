//! The sign-in methods this plane checks itself — an emailed code, a password — and
//! proving the signed-in account's own address later.
//!
//! Every answer is JSON, `{"ok":true}` or `{"error":"<code>"}` from one closed vocabulary,
//! so the sign-in dialog maps codes and never parses prose.
//!
//! The credential POSTs are reachable with no session, so the session's double-submit
//! check cannot guard them. Two things do instead: the `Origin` header must be this
//! plane's public origin or a host of a signing-in scope (a cross-site form cannot sign a
//! browser into an account of the attacker's choosing), and the ones that cost us a mail or test a password carry a
//! Turnstile token checked here.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, StatusCode},
	response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use domain::{
	auth::ProvenIdentity,
	error::DomainError,
	users::{Email, User, UserStatus, Username},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
	ports::{CodeIssue, CodePurpose, CodeRefusal, SignUp, VerifyRefusal},
	web::{
		WebState, now_secs,
		routes::{Caller, ClientIp, CsrfOutcome, clear_session, close, csrf_outcome, live_family_of, open_session, session_user},
	},
};

/// A refusal, as the dialog reads it.
pub struct Refusal(StatusCode, &'static str);

impl Refusal {
	pub(super) fn new(status: StatusCode, code: &'static str) -> Self {
		Self(status, code)
	}
}

impl IntoResponse for Refusal {
	fn into_response(self) -> Response {
		(self.0, Json(json!({ "error": self.1 }))).into_response()
	}
}

const INTERNAL: Refusal = Refusal(StatusCode::INTERNAL_SERVER_ERROR, "internal");

fn ok() -> Json<Value> {
	Json(json!({ "ok": true }))
}

pub(super) fn internal(context: &'static str, err: impl std::fmt::Display) -> Refusal {
	tracing::error!(error = %err, "{context}");
	INTERNAL
}

/// From this plane or a scope's host, and — when `turnstile` is given — a human. Only for
/// the scope routes `router` lists: a route acting on an open session must not widen its
/// origin through this.
pub(super) async fn guard(st: &super::Inner, headers: &HeaderMap, ip: &ClientIp, turnstile: Option<&str>) -> Result<(), Refusal> {
	if !headers.get("origin").and_then(|v| v.to_str().ok()).is_some_and(|origin| st.allowlist.admits(origin)) {
		return Err(Refusal(StatusCode::FORBIDDEN, "origin"));
	}
	match turnstile {
		Some(token) => human(st, ip, token).await,
		None => Ok(()),
	}
}

/// Cloudflare says a person solved the challenge, on one of our hosts. Fails closed when
/// siteverify cannot be asked.
pub(super) async fn human(st: &super::Inner, ip: &ClientIp, token: &str) -> Result<(), Refusal> {
	match st.turnstile.passes(token, &ip.0, |host| st.allowlist.admits_host(host)).await {
		Ok(true) => Ok(()),
		Ok(false) => Err(Refusal(StatusCode::FORBIDDEN, "captcha")),
		Err(e) => {
			tracing::error!(error = %e, "turnstile siteverify unreachable");
			Err(Refusal(StatusCode::SERVICE_UNAVAILABLE, "captcha_unavailable"))
		}
	}
}

fn email(raw: &str) -> Result<Email, Refusal> {
	Email::parse(raw).map_err(|_| Refusal(StatusCode::BAD_REQUEST, "invalid_email"))
}

pub(super) fn code_refusal(refusal: CodeRefusal) -> Refusal {
	match refusal {
		CodeRefusal::Missing | CodeRefusal::Wrong => Refusal(StatusCode::BAD_REQUEST, "invalid_code"),
		CodeRefusal::Expired => Refusal(StatusCode::BAD_REQUEST, "code_expired"),
		CodeRefusal::Exhausted => Refusal(StatusCode::BAD_REQUEST, "attempts_exceeded"),
	}
}

pub(super) async fn sent(st: &super::Inner, issue: CodeIssue) -> Result<Json<Value>, Refusal> {
	match issue {
		CodeIssue::Sent => {
			st.mail_wake.notify_one();
			Ok(ok())
		}
		CodeIssue::Throttled => Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "throttled")),
		CodeIssue::Exhausted => Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "attempts_exceeded")),
	}
}

/// A refusal of a signed-in route, with the cookies the browser must be left holding when
/// the session was read first: rotated, or cleared once the gate found it over.
pub struct Halt {
	jar: Option<CookieJar>,
	refusal: Refusal,
}

impl From<Refusal> for Halt {
	fn from(refusal: Refusal) -> Self {
		Self { jar: None, refusal }
	}
}

impl IntoResponse for Halt {
	fn into_response(self) -> Response {
		match self.jar {
			Some(jar) => (jar, self.refusal).into_response(),
			None => self.refusal.into_response(),
		}
	}
}

fn unauthenticated() -> Refusal {
	Refusal(StatusCode::UNAUTHORIZED, "unauthenticated")
}

/// Why [`gate`] refused: the session is over, or something else went wrong.
pub(super) enum Denied {
	SessionOver(Refusal),
	Other(Refusal),
}

impl From<Refusal> for Denied {
	fn from(refusal: Refusal) -> Self {
		Self::Other(refusal)
	}
}

/// The caller's account, gated as `authz::caller_gate` gates the gRPC surface and in its
/// order: a disabled account, or a session whose token predates the account's
/// `token_version`, is refused at once rather than when its access token next expires.
/// Both mean the session has nothing left to act for.
pub(super) async fn gate(st: &super::Inner, caller: &Caller) -> Result<User, Denied> {
	let user = st.users.find_by_id(caller.id).await.map_err(|e| internal("account: not read", e))?.ok_or_else(unauthenticated)?;
	if user.status() == UserStatus::Disabled {
		return Err(Denied::SessionOver(Refusal(StatusCode::FORBIDDEN, "disabled")));
	}
	if caller.minted_token_version.is_none_or(|minted| minted < user.token_version()) {
		return Err(Denied::SessionOver(unauthenticated()));
	}
	Ok(user)
}

/// End the browser's session as a sign-out does and hand back the jar that clears it.
pub(super) async fn end_session(st: &super::Inner, jar: CookieJar) -> CookieJar {
	if let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_owned())
		&& let Err(e) = close(st, &id).await
	{
		// The cookies are cleared regardless; a session the store still holds dies at its
		// next refresh, which re-reads the same account.
		tracing::error!(error = ?e, "session over but not closed");
	}
	clear_session(st, jar)
}

/// The signed-in caller of a state-changing route and their account, as [`gate`] admits it.
pub(super) struct Signed {
	pub(super) caller: Caller,
	pub(super) user: User,
}

/// The caller behind a state-changing request with a session: CSRF first, as everywhere,
/// then [`gate`].
pub(super) async fn signed_in(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<Signed, Halt> {
	match csrf_outcome(st, jar, headers).await.map_err(|_| INTERNAL)? {
		CsrfOutcome::Ok => {}
		CsrfOutcome::NoSession => return Err(unauthenticated().into()),
		CsrfOutcome::Mismatch => return Err(Refusal(StatusCode::FORBIDDEN, "csrf").into()),
	}
	let caller = session_user(st, jar).await.map_err(|_| INTERNAL)?.ok_or_else(unauthenticated)?;
	match gate(st, &caller).await {
		Ok(user) => Ok(Signed { caller, user }),
		Err(Denied::Other(refusal)) => Err(Halt {
			jar: Some(caller.refreshed(st, jar.clone())),
			refusal,
		}),
		Err(Denied::SessionOver(refusal)) => Err(Halt {
			jar: Some(end_session(st, jar.clone()).await),
			refusal,
		}),
	}
}

/// [`signed_in`] for a route that plants a credential (a passkey, a password): the refresh
/// family behind the session is checked first-hand as `/auth/authorize` checks it. The
/// session's cached access token outlives a sign-out from another device or a revoked
/// session, and a credential planted in that window would outlive the revocation.
pub(super) async fn signed_in_live(st: &super::Inner, jar: &CookieJar, headers: &HeaderMap) -> Result<Signed, Halt> {
	let signed = signed_in(st, jar, headers).await?;
	let Some(id) = jar.get(&st.cookies.session).map(|c| c.value().to_owned()) else {
		return Err(unauthenticated().into());
	};
	match live_family_of(st, &id).await {
		Ok(Some(_)) => Ok(signed),
		Ok(None) => Err(Halt {
			jar: Some(end_session(st, jar.clone()).await),
			refusal: unauthenticated(),
		}),
		Err(e) => Err(Halt {
			jar: Some(signed.caller.refreshed(st, jar.clone())),
			refusal: internal("session family not read", e),
		}),
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeRequest {
	email: String,
	turnstile_token: String,
}

/// `POST /auth/code/request` — mail a sign-in code. Answers the same for an address no
/// account holds: whether one does is decided only once the code proves the mailbox.
pub async fn request_code(State(st): State<WebState>, headers: HeaderMap, ip: ClientIp, Json(body): Json<CodeRequest>) -> Result<Json<Value>, Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, Some(&body.turnstile_token)).await?;
	let email = email(&body.email)?;
	let issue = st
		.credentials
		.issue_code(CodePurpose::Login(email), now_secs())
		.await
		.map_err(|e| internal("sign-in code not issued", e))?;
	sent(st, issue).await
}

#[derive(Deserialize)]
pub struct CodeVerify {
	email: String,
	code: String,
}

/// `POST /auth/code/verify` — spend the code and sign in to the account the mailbox opens
/// (`UserDirectoryRepository::resolve`), creating it when there is none.
pub async fn verify_code(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<CodeVerify>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, None).await?;
	let email = email(&body.email)?;
	st.credentials
		.redeem_login_code(&email, &body.code, now_secs())
		.await
		.map_err(|e| internal("sign-in code not redeemed", e))?
		.map_err(code_refusal)?;
	let identity = ProvenIdentity {
		provider: None,
		email,
		email_proven: true,
	};
	let user = st.users.resolve(identity, now_secs()).await.map_err(|e| internal("code sign-in: account resolution failed", e))?;
	signed_in_as(st, jar, &headers, &ip, user.id()).await
}

/// Open the session and answer the way every method here does.
pub(super) async fn signed_in_as(st: &super::Inner, jar: CookieJar, headers: &HeaderMap, ip: &ClientIp, user: domain::users::UserId) -> Result<(CookieJar, Json<Value>), Refusal> {
	match open_session(st, jar, headers, ip, user).await {
		Ok(jar) => Ok((jar, ok())),
		Err((_, "disabled")) => Err(Refusal(StatusCode::FORBIDDEN, "disabled")),
		Err(_) => Err(INTERNAL),
	}
}

/// A signed-in route's answer. Reading the session may have rotated it, so the refreshed
/// access cookie goes back with a refusal too.
pub(super) type Answered = Result<(CookieJar, Result<Json<Value>, Refusal>), Halt>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRequest {
	/// Defaulted so a client that predates the challenge (`{}`) is told `captcha` — a code
	/// the dialog maps — rather than refused by the body parser.
	#[serde(default)]
	turnstile_token: String,
}

/// `POST /auth/email/verify/request` — mail the signed-in account a code for its own
/// address. A mail costs us, so a person must be behind it, as on `/auth/code/request`: a
/// stolen session must not be a way to fill the owner's mailbox.
pub async fn request_verification(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<VerificationRequest>) -> Answered {
	let st = &st.inner;
	let Signed { caller, .. } = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match human(st, &ip, &body.turnstile_token).await {
		Ok(()) => match st.credentials.issue_code(CodePurpose::Verify(id), now_secs()).await {
			Ok(issue) => sent(st, issue).await,
			Err(e) => Err(internal("verification code not issued", e)),
		},
		Err(refusal) => Err(refusal),
	};
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct CodeOnly {
	code: String,
}

/// `POST /auth/email/verify/confirm` — spend it: the account's address is verified.
pub async fn confirm_verification(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<CodeOnly>) -> Answered {
	let st = &st.inner;
	let Signed { caller, .. } = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match st.credentials.verify_email(id, &body.code, now_secs()).await {
		Ok(Ok(_)) => Ok(ok()),
		Ok(Err(VerifyRefusal::Code(refusal))) => Err(code_refusal(refusal)),
		Ok(Err(VerifyRefusal::Taken)) => Err(Refusal(StatusCode::CONFLICT, "email_taken")),
		Err(e) => Err(internal("email not verified", e)),
	};
	Ok((jar, answer))
}

/// Long enough to resist guessing behind the lockout, short enough that argon2 never
/// hashes a megabyte on a stranger's behalf.
const PASSWORD_CHARS: std::ops::RangeInclusive<usize> = 8..=128;

fn acceptable(password: &str) -> Result<(), Refusal> {
	match PASSWORD_CHARS.contains(&password.chars().count()) {
		true => Ok(()),
		false => Err(Refusal(StatusCode::BAD_REQUEST, "weak_password")),
	}
}

/// argon2id with the crate's defaults (OWASP's m=19 MiB, t=2, p=1), off the async
/// workers: one hash is tens of milliseconds of CPU.
async fn hash(password: String) -> Result<String, Refusal> {
	tokio::task::spawn_blocking(move || {
		use argon2::password_hash::{PasswordHasher, SaltString};
		let mut salt = [0u8; 16];
		getrandom::fill(&mut salt).expect("CSPRNG unavailable");
		let salt = SaltString::encode_b64(&salt).expect("16 bytes is a valid salt");
		argon2::Argon2::default().hash_password(password.as_bytes(), &salt).map(|phc| phc.to_string())
	})
	.await
	.expect("hashing does not panic")
	.map_err(|e| internal("password not hashed", e))
}

async fn matches(phc: String, password: String) -> Result<bool, Refusal> {
	tokio::task::spawn_blocking(move || {
		use argon2::password_hash::{PasswordHash, PasswordVerifier};
		let parsed = PasswordHash::new(&phc).map_err(|e| e.to_string())?;
		Ok::<_, String>(argon2::Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
	})
	.await
	.expect("verifying does not panic")
	.map_err(|e| internal("stored password hash does not parse", e))
}

/// Verified when a handle names no password, so that answer costs what a wrong password
/// costs and the timing says nothing about who has an account.
static DECOY: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
	use argon2::password_hash::{PasswordHasher, SaltString};
	let salt = SaltString::encode_b64(b"concierge-decoy!").expect("16 bytes is a valid salt");
	argon2::Argon2::default().hash_password(b"no account has this password", &salt).expect("decoy hashes").to_string()
});

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
	email: String,
	password: String,
	/// "Verify my email now": mail a code as the account is made.
	verify: bool,
	turnstile_token: String,
}

/// `POST /auth/password/signup` — a new account behind an email and a password, signed in
/// at once and working unverified. Refused `email_taken` when the address already backs a
/// password or is verified on an account: that person signs in, with a code if they forgot.
/// Saying so tells the caller an account exists, which a sign-up by email cannot avoid.
pub async fn sign_up(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<SignUpRequest>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, Some(&body.turnstile_token)).await?;
	let email = email(&body.email)?;
	acceptable(&body.password)?;
	let phc = hash(body.password).await?;
	let user = match st.credentials.sign_up(&email, phc, now_secs()).await.map_err(|e| internal("sign-up failed", e))? {
		SignUp::Created(user) => user,
		SignUp::Taken => return Err(Refusal(StatusCode::CONFLICT, "email_taken")),
	};
	let verification = match body.verify {
		false => "skipped",
		true => match st.credentials.issue_code(CodePurpose::Verify(user.id()), now_secs()).await {
			Ok(CodeIssue::Sent) => {
				st.mail_wake.notify_one();
				"sent"
			}
			// An account made a moment ago has spent no verification budget; `Exhausted`
			// is listed only so that a new arm cannot pass unanswered.
			Ok(CodeIssue::Throttled | CodeIssue::Exhausted) => "throttled",
			Err(e) => {
				tracing::error!(error = %e, "sign-up: verification code not issued");
				"failed"
			}
		},
	};
	// The ticket goes with the code: it is what lets this browser confirm the address
	// from a scope's host, where it cannot read the CSRF cookie (`signup::confirm`).
	// A ticket that could not be stored is SAID, not only logged: the account exists and
	// is signed in, so failing the request would hide an account the user just made;
	// `ticket: null` with `ticket_error` tells the dialog to confirm on evinvest.ltd.
	// Whenever a code was ASKED for, sent or not: a throttled or failed send is exactly
	// what `signup::resend` recovers, and it needs the ticket to do it.
	let (ticket, ticket_error) = match body.verify {
		true => match super::signup::ticket_for(st, user.id()).await {
			Some(ticket) => (Some(ticket), None),
			None => (None, Some("ticket_unavailable")),
		},
		false => (None, None),
	};
	let (jar, _) = signed_in_as(st, jar, &headers, &ip, user.id()).await?;
	let mut answer = json!({ "ok": true, "verification": verification, "ticket": ticket });
	if let Some(error) = ticket_error {
		answer["ticket_error"] = json!(error);
	}
	Ok((jar, Json(answer)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRequest {
	/// An email or a username.
	identifier: String,
	password: String,
	turnstile_token: String,
}

/// `POST /auth/password/signin`. One refusal, `invalid_credentials`, for every handle and
/// password that do not match — except a locked password, which says so: the dialog then
/// offers a code, which the lock never blocks.
pub async fn sign_in(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<SignInRequest>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, Some(&body.turnstile_token)).await?;
	let invalid = Refusal(StatusCode::UNAUTHORIZED, "invalid_credentials");
	let Some(stored) = st.credentials.password_named(&body.identifier).await.map_err(|e| internal("password lookup failed", e))? else {
		matches(DECOY.clone(), body.password).await?;
		return Err(invalid);
	};
	let now = now_secs();
	if stored.locked_until.is_some_and(|until| until > now) {
		return Err(Refusal(StatusCode::TOO_MANY_REQUESTS, "password_locked"));
	}
	let right = matches(stored.phc, body.password).await?;
	st.credentials
		.record_password_attempt(stored.user, right, now)
		.await
		.map_err(|e| internal("password attempt not recorded", e))?;
	if !right {
		return Err(invalid);
	}
	signed_in_as(st, jar, &headers, &ip, stored.user).await
}

#[derive(Deserialize)]
pub struct SetPassword {
	password: String,
	code: String,
}

/// `POST /auth/password/set` — set or replace the password with a verification code
/// mailed by `/auth/email/verify/request`. "Forgot password" is a code sign-in, then this.
pub async fn set_password(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SetPassword>) -> Answered {
	let st = &st.inner;
	let Signed { caller, .. } = signed_in_live(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		acceptable(&body.password)?;
		let phc = hash(body.password).await?;
		match st.credentials.set_password(id, &body.code, phc, now_secs()).await.map_err(|e| internal("password not set", e))? {
			Ok(()) => Ok(ok()),
			Err(VerifyRefusal::Code(refusal)) => Err(code_refusal(refusal)),
			Err(VerifyRefusal::Taken) => Err(Refusal(StatusCode::CONFLICT, "email_taken")),
		}
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct SetUsername {
	username: String,
}

/// `POST /auth/username` — the signed-in account's chosen handle.
pub async fn set_username(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SetUsername>) -> Answered {
	let st = &st.inner;
	let Signed { caller, .. } = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match Username::parse(&body.username) {
		Err(_) => Err(Refusal(StatusCode::BAD_REQUEST, "invalid_username")),
		Ok(username) => match st.users.set_username(id, username).await {
			Ok(user) => Ok(Json(json!({ "ok": true, "username": user.username().map(Username::as_str) }))),
			Err(DomainError::Conflict(_)) => Err(Refusal(StatusCode::CONFLICT, "username_taken")),
			Err(e) => Err(internal("username not set", e)),
		},
	};
	Ok((jar, answer))
}

/// `GET /auth/methods` — how the signed-in account can sign in, for its settings.
pub async fn methods(State(st): State<WebState>, jar: CookieJar) -> Answered {
	let st = &st.inner;
	let caller = session_user(st, &jar).await.map_err(|_| INTERNAL)?.ok_or(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated"))?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match (st.credentials.methods(id).await, st.users.find_by_id(id).await) {
		(Ok(methods), Ok(Some(user))) => Ok(Json(json!({
			"email": user.email().as_str(),
			"emailVerified": user.email_verified(),
			"username": user.username().map(Username::as_str),
			"password": methods.password,
			"providers": methods.providers,
			"passkeys": methods.passkeys.iter().map(|p| json!({ "id": p.credential_id, "name": p.name, "createdAt": p.created_at, "lastUsedAt": p.last_used_at })).collect::<Vec<_>>(),
		}))),
		(Ok(_), Ok(None)) => Err(Refusal(StatusCode::UNAUTHORIZED, "unauthenticated")),
		(Err(e), _) | (_, Err(e)) => Err(internal("sign-in methods not read", e)),
	};
	Ok((jar, answer))
}
