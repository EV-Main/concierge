//! Re-authentication: the signed-in account proves itself AGAIN — a passkey, a mailed
//! code or its password — and the session's `auth_time` moves to now, with no new session.
//! A consumer that gates a sensitive act on "the user just confirmed" (`banking`'s
//! step-up) reads `auth_time` from the access token and sends the person here when it is
//! old.
//!
//! The verifiers are the sign-in ones (`sign_in`, `passkey`); what differs is who may be
//! proven. A sign-in resolves WHICH account a proof opens; here the account is already
//! fixed — the session's — so a proof is accepted only for exactly that account, and
//! nothing is resolved, linked or taken over. The routes are for `PUBLIC_ORIGIN` only
//! (not in the CORS list `router` keeps for scope hosts), CSRF-checked, and gated like
//! every credential-planting route: the refresh family is checked first-hand, so a
//! session revoked elsewhere cannot be refreshed back into a fresh `auth_time`.
//!
//! The answer is `{"ok":true,"authTime":<unix seconds>}` and the access cookie is re-set
//! to the token that carries it. Only the user's own access token gets the claim;
//! relying-party and service tokens never carry `auth_time`.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Deserialize;
use serde_json::{Value, json};
use tonic::Code;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential};

use crate::{
	ports::CodePurpose,
	web::{
		Inner, WebState, now_secs,
		passkey::{base64url, expired, rejected},
		routes::ClientIp,
		sign_in::{Answered, DECOY, Refusal, Signed, code_refusal, end_session, human, internal, matches, sent, signed_in_live},
	},
};

/// The budget window and size for [`Inner::reauth_attempts`]. A person re-authenticates
/// once, perhaps twice with a typo; ten in five minutes is generous for them and slow for
/// anyone grinding.
pub const WINDOW_SECS: u64 = 300;
pub const ATTEMPTS_PER_WINDOW: u32 = 10;

fn throttled() -> Refusal {
	Refusal::new(StatusCode::TOO_MANY_REQUESTS, "throttled")
}

fn spend(st: &Inner, user: UserId) -> Result<(), Refusal> {
	match st.reauth_attempts.check(&user.to_string()) {
		true => Ok(()),
		false => Err(throttled()),
	}
}

/// The proof held: move the session's `auth_time` and hand the browser the token that
/// carries it. The session ends when upstream says it is over, as everywhere else.
async fn moved(st: &Inner, jar: CookieJar, user: UserId) -> (CookieJar, Result<Json<Value>, Refusal>) {
	let Some(session) = jar.get(&st.cookies.session).map(|c| c.value().to_owned()) else {
		return (jar, Err(Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated")));
	};
	match st.sessions.reauthenticated(&session, &user.to_string(), &st.auth).await {
		Ok(Ok(done)) => {
			let jar = jar.add(st.cookies.server_cookie(st.cookies.access.clone(), done.access_token, done.remaining_secs));
			(jar, Ok(Json(json!({ "ok": true, "authTime": done.auth_time }))))
		}
		Ok(Err(status)) => match status.code() {
			Code::Unauthenticated => (end_session(st, jar).await, Err(Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated"))),
			Code::PermissionDenied => (end_session(st, jar).await, Err(Refusal::new(StatusCode::FORBIDDEN, "disabled"))),
			code => {
				tracing::error!(?code, detail = %status.message(), "reauth: issuance refused");
				(jar, Err(internal("reauth: auth_time not moved", status.message())))
			}
		},
		Err(e) => (jar, Err(internal("reauth: session store failed", format!("{e:?}")))),
	}
}

/// Mailing a code to the address costs us and proves the mailbox only when the address is
/// the account's verified one.
fn verified_address(user: &domain::users::User) -> Result<(), Refusal> {
	match user.email_verified() {
		true => Ok(()),
		false => Err(Refusal::new(StatusCode::FORBIDDEN, "email_unverified")),
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeRequest {
	/// Defaulted so a client that omits it is told `captcha`, a code the dialog maps.
	#[serde(default)]
	turnstile_token: String,
}

/// `POST /auth/reauth/code/request` — mail the signed-in account a sign-in code. A mail
/// costs us, so a person must be behind it, as on `/auth/code/request`.
pub async fn code_request(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Json(body): Json<CodeRequest>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in_live(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		spend(st, user.id())?;
		verified_address(&user)?;
		human(st, &ip, &body.turnstile_token).await?;
		let issue = st
			.credentials
			.issue_code(CodePurpose::Login(user.email().clone()), now_secs())
			.await
			.map_err(|e| internal("reauth: code not issued", e))?;
		sent(st, issue).await
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct CodeVerify {
	code: String,
}

/// `POST /auth/reauth/code/verify` — spend the mailed code. The mailbox it proves is the
/// account's own VERIFIED address, which belongs to this account alone
/// (`users_verified_email_idx`), so there is no one else it could open.
pub async fn code_verify(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<CodeVerify>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in_live(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	if let Err(refusal) = spend(st, user.id()).and_then(|()| verified_address(&user)) {
		return Ok((jar, Err(refusal)));
	}
	match st.credentials.redeem_login_code(user.email(), &body.code, now_secs()).await {
		Ok(Ok(())) => Ok(moved(st, jar, user.id()).await),
		Ok(Err(refusal)) => Ok((jar, Err(code_refusal(refusal)))),
		Err(e) => Ok((jar, Err(internal("reauth: code not redeemed", e)))),
	}
}

#[derive(Deserialize)]
pub struct PasswordBody {
	password: String,
}

/// `POST /auth/reauth/password` — the account's password. Shares the sign-in lockout
/// (`record_password_attempt`): ten failures lock the password for everyone, this route
/// included, and never the code or passkey paths.
pub async fn password(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<PasswordBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in_live(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let id = user.id();
	let invalid = || Refusal::new(StatusCode::UNAUTHORIZED, "invalid_credentials");
	let checked = async {
		spend(st, id)?;
		// Looked up by the address and then held to the session's account: the handle
		// can name another account, whose password proves nothing about this one.
		let stored = st
			.credentials
			.password_named(user.email().as_str())
			.await
			.map_err(|e| internal("reauth: password lookup failed", e))?;
		let Some(stored) = stored.filter(|s| s.user == id) else {
			matches(DECOY.clone(), body.password).await?;
			return Err(invalid());
		};
		let now = now_secs();
		if stored.locked_until.is_some_and(|until| until > now) {
			return Err(Refusal::new(StatusCode::TOO_MANY_REQUESTS, "password_locked"));
		}
		let right = matches(stored.phc, body.password).await?;
		st.credentials
			.record_password_attempt(id, right, now)
			.await
			.map_err(|e| internal("reauth: password attempt not recorded", e))?;
		right.then_some(()).ok_or_else(invalid)
	}
	.await;
	match checked {
		Ok(()) => Ok(moved(st, jar, id).await),
		Err(refusal) => Ok((jar, Err(refusal))),
	}
}

/// `POST /auth/reauth/passkey/options` — begin an assertion against the signed-in
/// account's own passkeys (not a discoverable one: the account is already named).
pub async fn passkey_options(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in_live(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let id = user.id();
	let answer = async {
		spend(st, id)?;
		let rows = st.credentials.passkeys(id).await.map_err(|e| internal("reauth: passkeys not read", e))?;
		let passkeys = rows
			.into_iter()
			.map(|row| serde_json::from_value::<Passkey>(row.passkey))
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| internal("reauth: a stored passkey does not parse", e))?;
		if passkeys.is_empty() {
			return Err(Refusal::new(StatusCode::BAD_REQUEST, "no_passkey"));
		}
		let webauthn = st.allowlist.current().webauthn.clone();
		let (options, state) = webauthn.start_passkey_authentication(&passkeys).map_err(|e| internal("reauth: assertion not begun", e))?;
		let ceremony = st.passkey_reauths.put((id, state, webauthn)).await;
		Ok(Json(json!({ "ceremony": ceremony, "options": options })))
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct PasskeyVerify {
	ceremony: String,
	credential: PublicKeyCredential,
}

/// `POST /auth/reauth/passkey/verify` — check the assertion against the passkey that was
/// offered, for the account that began the ceremony.
pub async fn passkey_verify(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<PasskeyVerify>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed_in_live(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let id = user.id();
	let checked = async {
		spend(st, id)?;
		let (owner, state, webauthn) = st.passkey_reauths.take(&body.ceremony).await.ok_or_else(expired)?;
		if owner != id {
			return Err(expired());
		}
		let result = webauthn.finish_passkey_authentication(&body.credential, &state).map_err(|e| {
			tracing::info!(error = %e, "reauth: assertion refused");
			rejected()
		})?;
		let credential_id = base64url(result.cred_id());
		let stored = st.credentials.passkeys(id).await.map_err(|e| internal("reauth: passkeys not read", e))?;
		let row = stored.into_iter().find(|row| row.credential_id == credential_id).ok_or_else(rejected)?;
		let mut passkey: Passkey = serde_json::from_value(row.passkey).map_err(|e| internal("reauth: a stored passkey does not parse", e))?;
		passkey.update_credential(&result);
		let updated = serde_json::to_value(&passkey).map_err(|e| internal("reauth: passkey not serialized", e))?;
		st.credentials
			.passkey_used(&credential_id, updated, now_secs())
			.await
			.map_err(|e| internal("reauth: passkey use not recorded", e))?;
		Ok(())
	}
	.await;
	match checked {
		Ok(()) => Ok(moved(st, jar, id).await),
		Err(refusal) => Ok((jar, Err(refusal))),
	}
}
