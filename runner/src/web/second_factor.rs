//! The account's second factors (`/auth/second-factor/*`): enrol one, prove one, remove
//! one, replace the recovery codes, recover with one of them.
//!
//! `PUBLIC_ORIGIN` only (never in the CORS list `router` keeps for scope hosts), CSRF-checked
//! and gated as every credential-planting route is (`signed_in_live`). Mounted only where
//! `SECOND_FACTOR_SEAL_KEY_FILE` is set; elsewhere every route answers 404.
//!
//! Who may change the factors: an account with none enrols its first on a fresh `auth_time`
//! (`require_fresh`), as a passkey is registered. Once it holds one, a fresh sign-in is not
//! enough — that is what a stolen session plus a mailbox can produce — and every change
//! wants the session to have proved a factor within [`FACTOR_FRESH_SECS`]
//! (`/auth/second-factor/verify`).
//!
//! A recovery code is for losing the factors, not for using them: it removes every factor
//! and code of the account and ends every session of it (`token_version` moves, so the money
//! plane sees `SESSIONS_REVOKED`). The person signs in again and enrols anew.

use std::{
	any::Any,
	collections::HashMap,
	sync::Arc,
	time::{Duration, Instant},
};

use axum::{
	Json,
	extract::State,
	http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use data_encoding::BASE32_NOPAD;
use domain::{error::DomainError, users::UserId};
use evconcierge_auth::stepup::Aal;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
	infrastructure::email::templates::breaks_or_hides,
	ports::{Attempt, Check, Enrolling, SealedFactor, SecondFactorRepository, Verdict},
	second_factor::{Binding, Checked, Corrupt, FactorKind, SealKey},
	web::{
		Inner, WebState, now_secs,
		reauth::{signed, verified_address},
		sign_in::{Answered, Refusal, Signed, end_session, internal, require_fresh},
	},
};

/// How long a proven factor lets the session change the account's factors.
pub const FACTOR_FRESH_SECS: u64 = 300;
/// How long a verification ceremony waits for its answer.
const CEREMONY_TTL: Duration = Duration::from_secs(300);
const MAX_CEREMONIES: usize = 10_000;
const RECOVERY_CODES: usize = 10;
/// 80 random bits a code: a digest at rest is out of reach of a guesser with the table.
const RECOVERY_CODE_BYTES: usize = 10;
const MAX_LABEL_CHARS: usize = 64;

/// What the composition root hands the web surface; `None` there means "not mounted".
pub struct SecondFactorDeps {
	pub seal: SealKey,
	pub store: Arc<dyn SecondFactorRepository>,
}

struct Ceremony {
	user: UserId,
	born: Instant,
	/// Each factor the options offered, with what its kind holds until the answer.
	pending: Vec<Pending>,
}

pub(super) struct SecondFactor {
	seal: Arc<SealKey>,
	pub(super) store: Arc<dyn SecondFactorRepository>,
	ceremonies: Mutex<HashMap<String, Ceremony>>,
}

impl SecondFactor {
	pub(super) fn new(deps: SecondFactorDeps) -> Self {
		Self {
			seal: Arc::new(deps.seal),
			store: deps.store,
			ceremonies: Mutex::new(HashMap::new()),
		}
	}

	async fn begin(&self, ceremony: Ceremony) -> (String, i64) {
		let id = super::random_token(24);
		let mut open = self.ceremonies.lock().await;
		open.retain(|_, c| c.born.elapsed() <= CEREMONY_TTL);
		// One open ceremony per account: a newer options call supersedes the older.
		open.retain(|_, c| c.user != ceremony.user);
		if open.len() >= MAX_CEREMONIES
			&& let Some(oldest) = open.iter().min_by_key(|(_, c)| c.born).map(|(k, _)| k.clone())
		{
			open.remove(&oldest);
		}
		open.insert(id.clone(), ceremony);
		(id, now_secs() + CEREMONY_TTL.as_secs() as i64)
	}

	/// The pending half for `factor`, spending the ceremony: one answer per ceremony.
	async fn take(&self, id: &str, user: UserId, factor: Uuid) -> Option<(FactorKind, Box<dyn Any + Send>)> {
		let ceremony = self.ceremonies.lock().await.remove(id)?;
		if ceremony.user != user || ceremony.born.elapsed() > CEREMONY_TTL {
			return None;
		}
		ceremony.pending.into_iter().find(|(id, ..)| *id == factor).map(|(_, kind, pending)| (kind, pending))
	}

	/// The check a repository runs on the locked row: open it, let its kind judge the
	/// answer, seal what the kind moved. `judge` is the kind's verification, or the end of
	/// its enrolment.
	fn check(&self, user: UserId, judge: impl FnOnce(FactorKind, &[u8]) -> Result<Checked, Corrupt> + Send + 'static) -> Check {
		let seal = self.seal.clone();
		Box::new(move |row: &SealedFactor| {
			let binding = Binding {
				factor: row.id,
				user,
				kind: row.kind,
			};
			let opened = seal
				.open(&binding, &row.material)
				.ok_or_else(|| DomainError::Repository(format!("second factor {} does not open under its own binding", row.id)))?;
			Ok(match judge(row.kind, &opened).map_err(|e| DomainError::Repository(format!("second factor {}: {e}", row.id)))? {
				Checked::Right(material) => Verdict::Right(seal.seal(&binding, &material)),
				Checked::Wrong => Verdict::Wrong,
				Checked::Malformed => Verdict::Malformed,
			})
		})
	}
}

fn mounted(st: &Inner) -> Result<&SecondFactor, Refusal> {
	st.second_factor.as_ref().ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "not_found"))
}

fn invalid(code: &'static str) -> Refusal {
	Refusal::new(StatusCode::BAD_REQUEST, code)
}

fn session_id(st: &Inner, jar: &CookieJar) -> Result<String, Refusal> {
	jar.get(&st.cookies.session)
		.map(|c| c.value().to_owned())
		.ok_or_else(|| Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated"))
}

/// `403 second_factor_required` unless this session proved a factor within
/// [`FACTOR_FRESH_SECS`]: the page runs `/auth/second-factor/verify` and retries.
async fn require_factor_fresh(st: &Inner, jar: &CookieJar) -> Result<(), Refusal> {
	let session = session_id(st, jar)?;
	match st.sessions.factor_fresh(&session).await {
		Ok(true) => Ok(()),
		Ok(false) => Err(Refusal::new(StatusCode::FORBIDDEN, "second_factor_required")),
		Err(e) => Err(internal("second factor: freshness not read", format!("{e:?}"))),
	}
}

/// A refusal for every answer that was not accepted.
pub(super) fn refused<T>(attempt: &Attempt<T>) -> Refusal {
	match attempt {
		Attempt::Accepted(_) => unreachable!("an accepted answer is not a refusal"),
		Attempt::Wrong => invalid("invalid_answer"),
		Attempt::Locked { .. } => Refusal::new(StatusCode::TOO_MANY_REQUESTS, "factor_locked"),
		Attempt::Unknown => invalid("unknown_factor"),
		Attempt::Malformed => invalid("invalid_request"),
	}
}

/// Fresh recovery codes, as shown once and as kept.
fn recovery_codes() -> (Vec<String>, Vec<[u8; 32]>) {
	(0..RECOVERY_CODES)
		.map(|_| {
			let mut raw = [0u8; RECOVERY_CODE_BYTES];
			getrandom::fill(&mut raw).expect("CSPRNG unavailable");
			let code = BASE32_NOPAD.encode(&raw).to_ascii_lowercase();
			let digest = recovery_digest(&code);
			let shown = code.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).expect("base32 is ascii")).collect::<Vec<_>>().join("-");
			(shown, digest)
		})
		.unzip()
}

/// A code as typed: case, dashes and spaces are not part of it.
fn recovery_digest(typed: &str) -> [u8; 32] {
	let normal: String = typed.chars().filter(|c| !matches!(c, '-' | ' ')).map(|c| c.to_ascii_lowercase()).collect();
	Sha256::digest(normal.as_bytes()).into()
}

fn label(raw: &str) -> Result<String, Refusal> {
	let label = raw.trim();
	if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS || label.chars().any(breaks_or_hides) {
		return Err(invalid("invalid_label"));
	}
	Ok(label.to_owned())
}

/// The account's factors as its settings show them; `null` where none can be enrolled.
pub(super) async fn summary(st: &Inner, user: UserId) -> Result<Value, Refusal> {
	let Some(sf) = st.second_factor.as_ref() else {
		return Ok(Value::Null);
	};
	let held = sf.store.second_factors(user).await.map_err(|e| internal("second factors not read", e))?;
	Ok(json!({
		"factors": held.factors.iter().map(|f| {
			let kind: &'static str = f.kind.into();
			json!({ "id": f.id, "kind": kind, "label": f.label, "createdAt": f.created_at, "lastUsedAt": f.last_used_at })
		}).collect::<Vec<_>>(),
		"recoveryCodesLeft": held.recovery_codes_left,
	}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolStart {
	kind: String,
	label: String,
}

/// `POST /auth/second-factor/enrol/start` — begin an enrolment: the offer (for an
/// authenticator app, its `otpauth://` URI and secret) is shown once, here.
pub async fn enrol_start(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<EnrolStart>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let fresh_sign_in = require_fresh(&caller);
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		let kind: FactorKind = body.kind.parse().map_err(|_| invalid("invalid_kind"))?;
		let label = label(&body.label)?;
		verified_address(&user)?;
		let held = sf.store.second_factors(user.id()).await.map_err(|e| internal("second factors not read", e))?;
		match held.factors.is_empty() {
			true => fresh_sign_in?,
			false => require_factor_fresh(st, &jar).await?,
		}
		let enrolment = kind.begin_enrol(user.email().as_str());
		let id = Uuid::new_v4();
		let material = sf.seal.seal(&Binding { factor: id, user: user.id(), kind }, &enrolment.enrolling);
		match sf
			.store
			.begin_enrolment(user.id(), SealedFactor { id, kind, material }, &label, now_secs())
			.await
			.map_err(|e| internal("second factor: enrolment not begun", e))?
		{
			Enrolling::Begun => Ok(Json(json!({
				"enrolment": id,
				"kind": body.kind,
				"offer": enrolment.offer,
				"expiresAt": now_secs() + crate::ports::SECOND_FACTOR_ENROLMENT_TTL_SECS,
			}))),
			Enrolling::Full => Err(Refusal::new(StatusCode::CONFLICT, "too_many_factors")),
		}
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolConfirm {
	enrolment: Uuid,
	response: Value,
}

/// `POST /auth/second-factor/enrol/confirm` — prove the new factor with its first answer.
/// The account's first factor comes with its recovery codes, shown once, here.
pub async fn enrol_confirm(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<EnrolConfirm>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		let now = now_secs();
		let response = body.response;
		let check = sf.check(user.id(), move |kind, enrolling| kind.finish_enrol(enrolling, response, now as u64));
		let (shown, kept) = recovery_codes();
		match sf
			.store
			.confirm_enrolment(user.id(), body.enrolment, check, kept, now)
			.await
			.map_err(|e| internal("second factor: enrolment not confirmed", e))?
		{
			Attempt::Accepted(confirmed) => {
				st.mail_wake.notify_one();
				tracing::info!(user = %user.id(), first = confirmed.first, "second factor enrolled");
				Ok(Json(json!({ "ok": true, "recoveryCodes": confirmed.first.then_some(shown) })))
			}
			Attempt::Unknown => Err(invalid("enrolment_expired")),
			other => Err(refused(&other)),
		}
	}
	.await;
	Ok((jar, answer))
}

/// What a factor holds between its challenge and its answer, by factor.
pub(super) type Pending = (Uuid, FactorKind, Box<dyn Any + Send>);

pub(super) struct Challenges {
	/// What the page is shown: each factor's id, kind, label and challenge.
	pub(super) offered: Vec<Value>,
	pub(super) pending: Vec<Pending>,
}

/// Challenge every factor of the account that gives at least `min_aal`.
/// `409 no_second_factor` when none does.
pub(super) async fn challenge(st: &Inner, user: UserId, min_aal: Aal) -> Result<Challenges, Refusal> {
	let sf = mounted(st)?;
	let held = sf.store.sealed_factors(user).await.map_err(|e| internal("second factors not read", e))?;
	let labels = sf.store.second_factors(user).await.map_err(|e| internal("second factors not read", e))?;
	let mut offered = Vec::new();
	let mut pending = Vec::new();
	for row in held.into_iter().filter(|row| row.kind.aal() >= min_aal) {
		let binding = Binding {
			factor: row.id,
			user,
			kind: row.kind,
		};
		let material = sf.seal.open(&binding, &row.material).ok_or_else(|| internal("second factor: material does not open", row.id))?;
		let challenged = row.kind.challenge(&material).map_err(|e| internal("second factor: not challenged", e))?;
		let kind: &'static str = row.kind.into();
		let label = labels.factors.iter().find(|f| f.id == row.id).map(|f| f.label.clone());
		offered.push(json!({ "id": row.id, "kind": kind, "label": label, "challenge": challenged.challenge }));
		pending.push((row.id, row.kind, challenged.pending));
	}
	if offered.is_empty() {
		return Err(Refusal::new(StatusCode::CONFLICT, "no_second_factor"));
	}
	Ok(Challenges { offered, pending })
}

/// Check `response` against `factor`, counted by the account's guard.
pub(super) async fn answer(st: &Inner, user: UserId, factor: Uuid, pending: Box<dyn Any + Send>, response: Value) -> Result<Attempt<()>, Refusal> {
	let sf = mounted(st)?;
	let now = now_secs();
	let check = sf.check(user, move |kind, material| kind.verify(material, pending, response, now as u64));
	sf.store.attempt(user, factor, check, now).await.map_err(|e| internal("second factor: answer not checked", e))
}

/// `POST /auth/second-factor/verify/options` — the account's factors and what each is
/// challenged with, under one ceremony.
pub async fn verify_options(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		let Challenges { offered, pending } = challenge(st, user.id(), Aal::SECOND_FACTOR).await?;
		let (ceremony, expires_at) = sf
			.begin(Ceremony {
				user: user.id(),
				born: Instant::now(),
				pending,
			})
			.await;
		Ok(Json(json!({ "ceremony": ceremony, "factors": offered, "expiresAt": expires_at })))
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
	ceremony: String,
	factor: Uuid,
	response: Value,
}

/// `POST /auth/second-factor/verify` — answer one factor of the ceremony. The session may
/// then change the account's factors for [`FACTOR_FRESH_SECS`].
pub async fn verify(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<VerifyBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		let session = session_id(st, &jar)?;
		let (_, pending) = sf.take(&body.ceremony, user.id(), body.factor).await.ok_or_else(|| invalid("ceremony_expired"))?;
		match answer(st, user.id(), body.factor, pending, body.response).await? {
			Attempt::Accepted(()) => {
				st.sessions
					.mark_factor_fresh(&session, FACTOR_FRESH_SECS)
					.await
					.map_err(|e| internal("second factor: freshness not kept", format!("{e:?}")))?;
				Ok(Json(json!({ "ok": true })))
			}
			other => Err(refused(&other)),
		}
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveBody {
	factor: Uuid,
}

/// `POST /auth/second-factor/remove` — the last factor takes the recovery codes with it,
/// and the money plane then refuses what it asks a factor for until a new one is enrolled.
pub async fn remove(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<RemoveBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		require_factor_fresh(st, &jar).await?;
		match sf.store.remove(user.id(), body.factor, now_secs()).await.map_err(|e| internal("second factor: not removed", e))? {
			Some(removed) => {
				st.mail_wake.notify_one();
				tracing::info!(user = %user.id(), remaining = removed.remaining, "second factor removed");
				Ok(Json(json!({ "ok": true, "remaining": removed.remaining })))
			}
			None => Err(invalid("unknown_factor")),
		}
	}
	.await;
	Ok((jar, answer))
}

/// `POST /auth/second-factor/recovery-codes` — a new set, shown once; the old set is void.
pub async fn replace_recovery_codes(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let sf = mounted(st)?;
		require_factor_fresh(st, &jar).await?;
		let (shown, kept) = recovery_codes();
		match sf
			.store
			.replace_recovery_codes(user.id(), kept, now_secs())
			.await
			.map_err(|e| internal("second factor: recovery codes not replaced", e))?
		{
			true => {
				st.mail_wake.notify_one();
				Ok(Json(json!({ "recoveryCodes": shown })))
			}
			false => Err(Refusal::new(StatusCode::CONFLICT, "no_second_factor")),
		}
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverBody {
	code: String,
}

/// `POST /auth/second-factor/recover` — spend a recovery code: every factor and code goes,
/// and every session of the account ends, this one included.
pub async fn recover(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<RecoverBody>) -> Answered {
	let st = &st.inner;
	let Signed { caller, user } = signed(st, &jar, &headers).await?;
	let fresh_sign_in = require_fresh(&caller);
	let refreshed = caller.refreshed(st, jar.clone());
	let checked = async {
		let sf = mounted(st)?;
		fresh_sign_in?;
		match sf
			.store
			.recover(user.id(), recovery_digest(&body.code), now_secs())
			.await
			.map_err(|e| internal("second factor: recovery not checked", e))?
		{
			Attempt::Accepted(()) => Ok(()),
			Attempt::Wrong => Err(invalid("invalid_code")),
			other => Err(refused(&other)),
		}
	}
	.await;
	match checked {
		Ok(()) => {
			st.mail_wake.notify_one();
			tracing::warn!(user = %user.id(), "second factors recovered: all removed, every session ended");
			Ok((end_session(st, jar).await, Ok(Json(json!({ "ok": true })))))
		}
		Err(refusal) => Ok((refreshed, Err(refusal))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_recovery_code_reads_the_same_however_it_is_typed() {
		let (shown, kept) = recovery_codes();
		assert_eq!(shown.len(), RECOVERY_CODES);
		let code = &shown[0];
		assert_eq!(code.len(), 19, "four groups of four: {code}");
		assert_eq!(recovery_digest(code), kept[0]);
		assert_eq!(recovery_digest(&code.to_ascii_uppercase().replace('-', " ")), kept[0]);
		assert_ne!(recovery_digest(&shown[1]), kept[0]);
	}
}
