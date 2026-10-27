//! Confirming a password sign-up's address from wherever the sign-up happened — a scope's
//! host included — without the CSRF double-submit `/auth/email/verify/confirm` asks for.
//!
//! The sign-up answers with a ticket beside the mailed code; this step spends both. It
//! verifies the address on the account that was just made and keeps its password. A
//! code SIGN-IN would instead read the same mailbox as a takeover of an unverified
//! password account (sessions revoked, password dropped) — right against a squatter, who
//! has no ticket, and wrong against the person who signed up a minute ago, who does.

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
	ports::{SignUpConfirmRefusal, VerifyRefusal},
	web::{
		WebState, now_secs, random_token,
		routes::ClientIp,
		sign_in::{Body, Refusal, code_refusal, guard, internal, sent, signed_in_as},
	},
};

fn digest(ticket: &str) -> [u8; 32] {
	Sha256::digest(ticket.as_bytes()).into()
}

/// A fresh ticket for `user`'s sign-up, or `None` — logged — when it could not be stored.
/// Its absence costs the caller the scope-host path only: the address can still be
/// confirmed on evinvest.ltd.
pub(super) async fn ticket_for(st: &super::Inner, user: UserId) -> Option<String> {
	let ticket = random_token(32);
	match st.credentials.issue_signup_ticket(user, &digest(&ticket), now_secs()).await {
		Ok(()) => Some(ticket),
		Err(e) => {
			tracing::error!(error = %e, %user, "sign-up: ticket not issued");
			None
		}
	}
}

#[derive(Deserialize)]
pub struct SignUpConfirm {
	ticket: String,
	code: String,
}

/// `POST /auth/password/signup/confirm` — verify the address and sign in. A ticket that
/// is unknown, spent, expired, someone else's or outlived by a new password answers
/// exactly as a wrong code does, so the ticket cannot be probed apart from the code. No
/// Turnstile: the code proves the mailbox, as on `/auth/code/verify`, and its attempts
/// are counted.
pub async fn confirm(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, ip: ClientIp, Body(body): Body<SignUpConfirm>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, None).await?;
	match st.credentials.confirm_signup(&digest(&body.ticket), &body.code, now_secs()).await {
		Ok(Ok(user)) => signed_in_as(st, jar, &headers, &ip, user.id()).await,
		Ok(Err(SignUpConfirmRefusal::Ticket)) => Err(Refusal::new(StatusCode::BAD_REQUEST, "invalid_code")),
		Ok(Err(SignUpConfirmRefusal::Disabled)) => Err(Refusal::new(StatusCode::FORBIDDEN, "disabled")),
		Ok(Err(SignUpConfirmRefusal::Verify(VerifyRefusal::Code(refusal)))) => Err(code_refusal(refusal)),
		Ok(Err(SignUpConfirmRefusal::Verify(VerifyRefusal::Taken))) => Err(Refusal::new(StatusCode::CONFLICT, "email_taken")),
		Err(e) => Err(internal("sign-up: not confirmed", e)),
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpResend {
	ticket: String,
	turnstile_token: String,
}

/// `POST /auth/password/signup/resend` — a new code for the sign-up under the same ticket,
/// to the account's address: a late mail, a throttled or failed first send, or a code that
/// expired while the tab sat open is recovered without the CSRF path. A mail costs us, so
/// Turnstile and the per-address throttle apply as on `/auth/code/request`. A ticket that
/// speaks for nobody answers `{ok:true}` and mails nothing — the same as a live one — so
/// a ticket cannot be probed here apart from the code; only a live ticket can be throttled.
pub async fn resend(State(st): State<WebState>, headers: HeaderMap, ip: ClientIp, Body(body): Body<SignUpResend>) -> Result<Json<Value>, Refusal> {
	let st = &st.inner;
	guard(st, &headers, &ip, Some(&body.turnstile_token)).await?;
	match st.credentials.resend_signup_code(&digest(&body.ticket), now_secs()).await {
		Ok(Some(issue)) => sent(st, issue).await,
		Ok(None) => Ok(Json(json!({ "ok": true }))),
		Err(e) => Err(internal("sign-up: code not resent", e)),
	}
}
