//! Postgres adapter for the credentials this plane checks itself: emailed one-time codes
//! (and passwords, beside them). The code shape is the consilium self-decision code's: a
//! digest at rest, attempts counted before the comparison in the same transaction, burned
//! on the last wrong guess, compared in constant time. The plaintext lives only in the
//! queued mail's payload, which the dispatcher strikes once the mail is sent or parked.

use async_trait::async_trait;
use domain::{
	error::DomainError,
	users::{AuthSubject, Email, User, UserId, UserStatus},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::users::{Named, account_named, drain_outbox, free_username, insert_user, load_for_update, lock_email, update_row, verified_holder};
use crate::ports::{
	CODE_MAX_ATTEMPTS, CODE_SEND_WINDOW_SECS, CODE_SENDS_PER_WINDOW, CODE_TTL_SECS, CodeIssue, CodePurpose, CodeRefusal, CredentialRepository, PASSWORD_LOCK_SECS, PASSWORD_MAX_FAILURES,
	PasskeyRow, SIGNUP_TICKET_TTL_SECS, SignInMethods, SignUp, SignUpConfirmRefusal, StoredPassword, VERIFY_BUDGET_WINDOW_SECS, VERIFY_CODES_PER_DAY, VERIFY_WRONG_PER_DAY, VerifyRefusal,
};

/// How long a spent or expired sign-up ticket row is kept before the insert path reaps it.
const TICKET_RETENTION_SECS: i64 = 24 * 60 * 60;

pub struct PgCredentials {
	pool: PgPool,
}

impl PgCredentials {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

/// Six uniform digits. Rejection sampling, so no code is likelier than another.
fn six_digits() -> String {
	const SPAN: u32 = 1_000_000;
	let limit = u32::MAX - u32::MAX % SPAN;
	loop {
		let mut bytes = [0u8; 4];
		getrandom::fill(&mut bytes).expect("CSPRNG unavailable");
		let n = u32::from_le_bytes(bytes);
		if n < limit {
			return format!("{:06}", n % SPAN);
		}
	}
}

/// Bound to the row, so equal codes on two rows never share a digest.
fn digest(id: Uuid, code: &str) -> Vec<u8> {
	let mut hasher = Sha256::new();
	hasher.update(id.as_bytes());
	hasher.update(code.as_bytes());
	hasher.finalize().to_vec()
}

#[derive(sqlx::FromRow)]
struct CodeRow {
	id: Uuid,
	code_hash: Vec<u8>,
	expires_at: i64,
	attempts: i32,
	burned_at: Option<i64>,
	binding: Option<Vec<u8>>,
}

/// Spend the live code sent to `email` for `purpose` (and `user`, for a verification).
/// Issuing one burns its predecessors, so there is at most one to compare against.
async fn redeem(
	conn: &mut PgConnection,
	email: &Email,
	purpose: &str,
	user: Option<UserId>,
	binding: Option<&[u8; 32]>,
	code: &str,
	now: i64,
) -> Result<Result<(), CodeRefusal>, DomainError> {
	let Some(row) = sqlx::query_as::<_, CodeRow>(
		"SELECT id, code_hash, expires_at, attempts, burned_at, binding FROM email_codes \
		 WHERE email = $1 AND purpose = $2 AND user_id IS NOT DISTINCT FROM $3 \
		 ORDER BY burned_at IS NULL DESC, created_at DESC LIMIT 1 FOR UPDATE",
	)
	.bind(email.as_str())
	.bind(purpose)
	.bind(user.map(|u| u.raw()))
	.fetch_optional(&mut *conn)
	.await
	.map_err(repo_err)?
	else {
		return Ok(Err(CodeRefusal::Missing));
	};
	// A code issued for another operation is no code for this one. Refused before anything
	// is counted: the guess is not a guess at this operation's code.
	if let Some(wanted) = binding
		&& row.binding.as_deref() != Some(wanted.as_slice())
	{
		return Ok(Err(CodeRefusal::Missing));
	}
	if row.burned_at.is_some() {
		return Ok(Err(if row.attempts >= CODE_MAX_ATTEMPTS { CodeRefusal::Exhausted } else { CodeRefusal::Missing }));
	}
	if row.expires_at <= now {
		return Ok(Err(CodeRefusal::Expired));
	}
	if let Some(user) = user
		&& verify_spent(conn, email, user, purpose, now).await?.wrong >= VERIFY_WRONG_PER_DAY
	{
		return Ok(Err(CodeRefusal::Exhausted));
	}
	let attempts = row.attempts + 1;
	let presented = digest(row.id, code.trim());
	let matches = presented.len() == row.code_hash.len() && bool::from(presented.ct_eq(&row.code_hash));
	let burned = matches || attempts >= CODE_MAX_ATTEMPTS;
	// `attempts` stores WRONG guesses only, so the account's daily sum is a count of them.
	sqlx::query("UPDATE email_codes SET attempts = $2, burned_at = $3 WHERE id = $1")
		.bind(row.id)
		.bind(if matches { row.attempts } else { attempts })
		.bind(burned.then_some(now))
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(match (matches, burned) {
		(true, _) => Ok(()),
		(false, true) => Err(CodeRefusal::Exhausted),
		(false, false) => Err(CodeRefusal::Wrong),
	})
}

/// The account's address, read WITHOUT the row lock: the email lock comes first, here as
/// in `resolve`, or the two would deadlock each other.
async fn email_of(conn: &mut PgConnection, user: UserId) -> Result<Email, DomainError> {
	let raw: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?
		.ok_or_else(|| DomainError::NotFound {
			entity: "user",
			id: user.to_string(),
		})?;
	Email::parse(&raw)
}

#[async_trait]
impl CredentialRepository for PgCredentials {
	async fn issue_code(&self, purpose: CodePurpose, now: i64) -> Result<CodeIssue, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let issue = issue_in(&mut tx, purpose, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(issue)
	}

	async fn redeem_login_code(&self, email: &Email, code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = redeem(&mut tx, email, "login", None, None, code, now).await?;
		// Committed whatever the outcome: a wrong guess must stay counted.
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn redeem_reauth_code(&self, user: UserId, code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// The address is read first and locked second, as `issue_in` does.
		let email = email_of(&mut tx, user).await?;
		lock_email(&mut tx, &email).await?;
		let outcome = redeem(&mut tx, &email, "reauth", Some(user), None, code, now).await?;
		// Committed whatever the outcome: a wrong guess must stay counted.
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn issue_stepup_code(&self, user: UserId, binding: [u8; 32], context: serde_json::Value, ttl_secs: i64, now: i64) -> Result<CodeIssue, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let email = email_of(&mut tx, user).await?;
		lock_email(&mut tx, &email).await?;
		let issue = issue_locked_with(
			&mut tx,
			&email,
			"stepup",
			Some(user),
			now,
			Issue {
				ttl_secs,
				binding: Some(&binding),
				context: Some(&context),
			},
		)
		.await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(issue)
	}

	async fn redeem_stepup_code(&self, user: UserId, binding: [u8; 32], code: &str, now: i64) -> Result<Result<(), CodeRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let email = email_of(&mut tx, user).await?;
		lock_email(&mut tx, &email).await?;
		let outcome = redeem(&mut tx, &email, "stepup", Some(user), Some(&binding), code, now).await?;
		// Committed whatever the outcome: a wrong guess must stay counted.
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn verify_email(&self, user: UserId, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = verify_with_code(&mut tx, user, code, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn sign_up(&self, email: &Email, phc: String, now: i64) -> Result<SignUp, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_email(&mut tx, email).await?;
		let backs_password: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN password_credentials p ON p.user_id = u.id WHERE lower(u.email) = $1)")
			.bind(email.as_str())
			.fetch_one(&mut *tx)
			.await
			.map_err(repo_err)?;
		if backs_password || verified_holder(&mut tx, email).await?.is_some() {
			return Ok(SignUp::Taken);
		}
		let id = UserId::new();
		let user = User::provision(id, AuthSubject::parse(&id.to_string())?, email.clone(), false, free_username(&mut tx, email, None).await?);
		let mut user = insert_user(&mut tx, user).await?;
		write_password(&mut tx, id, &phc, now).await?;
		drain_outbox(&mut tx, &mut user).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(SignUp::Created(Box::new(user)))
	}

	async fn password_named(&self, handle: &str) -> Result<Option<StoredPassword>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let Named::One(user) = account_named(&mut conn, handle).await? else {
			return Ok(None);
		};
		let row: Option<(String, Option<i64>)> = sqlx::query_as("SELECT phc, locked_until FROM password_credentials WHERE user_id = $1")
			.bind(user.raw())
			.fetch_optional(&mut *conn)
			.await
			.map_err(repo_err)?;
		Ok(row.map(|(phc, locked_until)| StoredPassword { user, phc, locked_until }))
	}

	async fn record_password_attempt(&self, user: UserId, succeeded: bool, now: i64) -> Result<(), DomainError> {
		let query = match succeeded {
			true => sqlx::query("UPDATE password_credentials SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1").bind(user.raw()),
			false => sqlx::query(
				"UPDATE password_credentials SET \
				 locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN $3 + $4 ELSE locked_until END, \
				 failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END \
				 WHERE user_id = $1",
			)
			.bind(user.raw())
			.bind(PASSWORD_MAX_FAILURES)
			.bind(now)
			.bind(PASSWORD_LOCK_SECS),
		};
		query.execute(&self.pool).await.map_err(repo_err)?;
		Ok(())
	}

	async fn methods(&self, user: UserId) -> Result<SignInMethods, DomainError> {
		let password: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM password_credentials WHERE user_id = $1)")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		let providers = sqlx::query_scalar("SELECT provider FROM user_identities WHERE user_id = $1 ORDER BY provider")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(SignInMethods {
			password,
			providers,
			passkeys: self.passkeys(user).await?,
		})
	}

	async fn passkeys(&self, user: UserId) -> Result<Vec<PasskeyRow>, DomainError> {
		let rows: Vec<(String, serde_json::Value, String, i64, Option<i64>)> =
			sqlx::query_as("SELECT credential_id, passkey, name, created_at, last_used_at FROM passkey_credentials WHERE user_id = $1 ORDER BY created_at, credential_id")
				.bind(user.raw())
				.fetch_all(&self.pool)
				.await
				.map_err(repo_err)?;
		Ok(rows
			.into_iter()
			.map(|(credential_id, passkey, name, created_at, last_used_at)| PasskeyRow {
				credential_id,
				passkey,
				name,
				created_at,
				last_used_at,
			})
			.collect())
	}

	async fn add_passkey(&self, user: UserId, passkey: PasskeyRow) -> Result<bool, DomainError> {
		let inserted = sqlx::query("INSERT INTO passkey_credentials (credential_id, user_id, passkey, name, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (credential_id) DO NOTHING")
			.bind(&passkey.credential_id)
			.bind(user.raw())
			.bind(&passkey.passkey)
			.bind(&passkey.name)
			.bind(passkey.created_at)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(inserted.rows_affected() == 1)
	}

	async fn passkey_used(&self, credential_id: &str, passkey: serde_json::Value, now: i64) -> Result<(), DomainError> {
		sqlx::query("UPDATE passkey_credentials SET passkey = $2, last_used_at = $3 WHERE credential_id = $1")
			.bind(credential_id)
			.bind(passkey)
			.bind(now)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(())
	}

	async fn remove_passkey(&self, user: UserId, credential_id: &str) -> Result<bool, DomainError> {
		let removed = sqlx::query("DELETE FROM passkey_credentials WHERE user_id = $1 AND credential_id = $2")
			.bind(user.raw())
			.bind(credential_id)
			.execute(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(removed.rows_affected() == 1)
	}

	async fn issue_signup_ticket(&self, user: UserId, ticket_hash: &[u8], now: i64) -> Result<(), DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// Reaped here rather than by a sweeper: the table only grows on this path.
		sqlx::query("DELETE FROM signup_tickets WHERE expires_at < $1")
			.bind(now - TICKET_RETENTION_SECS)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		let inserted = sqlx::query(
			"INSERT INTO signup_tickets (ticket_hash, user_id, token_version, password_set_at, issued_at, expires_at)
			 SELECT $1, u.id, u.token_version, p.updated_at, $3, $3 + $4
			 FROM users u JOIN password_credentials p ON p.user_id = u.id WHERE u.id = $2",
		)
		.bind(ticket_hash)
		.bind(user.raw())
		.bind(now)
		.bind(SIGNUP_TICKET_TTL_SECS)
		.execute(&mut *tx)
		.await
		.map_err(repo_err)?;
		if inserted.rows_affected() == 0 {
			return Err(DomainError::NotFound {
				entity: "password account",
				id: user.to_string(),
			});
		}
		tx.commit().await.map_err(repo_err)
	}

	async fn confirm_signup(&self, ticket_hash: &[u8], code: &str, now: i64) -> Result<Result<User, SignUpConfirmRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let Some((account, email)) = live_ticket(&mut tx, ticket_hash, now).await? else {
			return Ok(Err(SignUpConfirmRefusal::Ticket));
		};
		// Before anything is written: a refusal here verifies no address, spends no code
		// and keeps the ticket. The transaction is dropped, not committed.
		if account.status() == UserStatus::Disabled {
			return Ok(Err(SignUpConfirmRefusal::Disabled));
		}
		let outcome = verify_locked(&mut tx, account, &email, code, now).await?;
		if outcome.is_ok() {
			sqlx::query("UPDATE signup_tickets SET spent_at = $2 WHERE ticket_hash = $1")
				.bind(ticket_hash)
				.bind(now)
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
		}
		// Committed whatever the outcome: a wrong guess must stay counted against the code.
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome.map_err(SignUpConfirmRefusal::Verify))
	}

	async fn resend_signup_code(&self, ticket_hash: &[u8], now: i64) -> Result<Option<CodeIssue>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let Some((account, email)) = live_ticket(&mut tx, ticket_hash, now).await?.filter(|(account, _)| account.status() != UserStatus::Disabled) else {
			return Ok(None);
		};
		let issue = issue_locked(&mut tx, &email, "verify", Some(account.id()), now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Some(issue))
	}

	async fn set_password(&self, user: UserId, code: &str, phc: String, now: i64) -> Result<Result<(), VerifyRefusal>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let outcome = verify_with_code(&mut tx, user, code, now).await?;
		if outcome.is_ok() {
			write_password(&mut tx, user, &phc, now).await?;
		}
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome.map(|_| ()))
	}
}

/// Mint a code and queue its mail inside the caller's transaction; a throttled send
/// writes nothing.
async fn issue_in(conn: &mut PgConnection, purpose: CodePurpose, now: i64) -> Result<CodeIssue, DomainError> {
	let (email, purpose, user) = match purpose {
		CodePurpose::Login(email) => (email, "login", None),
		CodePurpose::Verify(user) => (email_of(conn, user).await?, "verify", Some(user)),
		CodePurpose::Reauth(user) => (email_of(conn, user).await?, "reauth", Some(user)),
	};
	lock_email(conn, &email).await?;
	issue_locked(conn, &email, purpose, user, now).await
}

/// What one account spent of its daily budget, for one account-bound `purpose`, on its address.
struct VerifySpent {
	issued: i64,
	wrong: i64,
}

/// Counted on the account's current address as well as its id: a code sent to an address
/// it no longer has can verify nothing, and the address leads the only index the table has.
async fn verify_spent(conn: &mut PgConnection, email: &Email, user: UserId, purpose: &str, now: i64) -> Result<VerifySpent, DomainError> {
	let (issued, wrong): (i64, i64) = sqlx::query_as(
		"SELECT count(*), COALESCE(sum(attempts), 0)::BIGINT FROM email_codes \
		 WHERE email = $1 AND purpose = $4 AND user_id = $2 AND created_at > $3",
	)
	.bind(email.as_str())
	.bind(user.raw())
	.bind(now - VERIFY_BUDGET_WINDOW_SECS)
	.bind(purpose)
	.fetch_one(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(VerifySpent { issued, wrong })
}

/// [`issue_in`] for a caller already holding `email`'s lock.
async fn issue_locked(conn: &mut PgConnection, email: &Email, purpose: &str, user: Option<UserId>, now: i64) -> Result<CodeIssue, DomainError> {
	let extras = Issue {
		ttl_secs: CODE_TTL_SECS,
		binding: None,
		context: None,
	};
	issue_locked_with(conn, email, purpose, user, now, extras).await
}

/// What a code is issued with beyond who it is for.
struct Issue<'a> {
	ttl_secs: i64,
	/// The operation a step-up code is for.
	binding: Option<&'a [u8; 32]>,
	/// Extra fields for the mail's payload.
	context: Option<&'a serde_json::Value>,
}

/// [`issue_locked`] with the code's lifetime and extra fields for the mail's payload. The
/// extras never override the code or its expiry: they describe what the code is for.
async fn issue_locked_with(conn: &mut PgConnection, email: &Email, purpose: &str, user: Option<UserId>, now: i64, extras: Issue<'_>) -> Result<CodeIssue, DomainError> {
	let Issue { ttl_secs, binding, context } = extras;
	// The guess cap first: it outlasts the send window, so it is the answer worth giving.
	if let Some(user) = user {
		let spent = verify_spent(conn, email, user, purpose, now).await?;
		if spent.wrong >= VERIFY_WRONG_PER_DAY {
			return Ok(CodeIssue::Exhausted);
		}
		if spent.issued >= VERIFY_CODES_PER_DAY {
			return Ok(CodeIssue::Throttled);
		}
	}
	let recent: i64 = sqlx::query_scalar("SELECT count(*) FROM email_codes WHERE email = $1 AND purpose = $2 AND created_at > $3")
		.bind(email.as_str())
		.bind(purpose)
		.bind(now - CODE_SEND_WINDOW_SECS)
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)?;
	if recent >= CODE_SENDS_PER_WINDOW {
		return Ok(CodeIssue::Throttled);
	}
	sqlx::query("UPDATE email_codes SET burned_at = $4 WHERE email = $1 AND purpose = $2 AND user_id IS NOT DISTINCT FROM $3 AND burned_at IS NULL")
		.bind(email.as_str())
		.bind(purpose)
		.bind(user.map(|u| u.raw()))
		.bind(now)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	let id = Uuid::new_v4();
	let code = six_digits();
	let expires_at = now + ttl_secs;
	sqlx::query("INSERT INTO email_codes (id, email, purpose, user_id, code_hash, expires_at, created_at, binding) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
		.bind(id)
		.bind(email.as_str())
		.bind(purpose)
		.bind(user.map(|u| u.raw()))
		.bind(digest(id, &code))
		.bind(expires_at)
		.bind(now)
		.bind(binding.map(|b| b.to_vec()))
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	sqlx::query("INSERT INTO notification_deliveries (kind, recipient, dedupe_key, payload) VALUES ('email_code', $1, $2, $3)")
		.bind(email.as_str())
		.bind(format!("email_code:{id}"))
		.bind(delivery_payload(purpose, &code, expires_at, context))
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(CodeIssue::Sent)
}

/// The `email_code` delivery's payload: the context first, so a context key can never
/// replace the three that make it a code.
fn delivery_payload(purpose: &str, code: &str, expires_at: i64, context: Option<&serde_json::Value>) -> serde_json::Value {
	let mut payload = context.and_then(|c| c.as_object().cloned()).unwrap_or_default();
	payload.insert("purpose".into(), purpose.into());
	payload.insert("code".into(), code.into());
	payload.insert("expires_at".into(), expires_at.into());
	serde_json::Value::Object(payload)
}

/// The account a sign-up ticket still speaks for, with its address, or `None`. The
/// ticket row, the mailbox lock and the account's rows are held to the end of the
/// caller's transaction, taken in the order every other writer of the mailbox takes them
/// (advisory lock, then the row), so nothing that would kill the ticket — a takeover, a
/// revoke-all, a new password — can land between this check and what the caller does on
/// its strength. The caller works on the account and address returned, never re-locking.
async fn live_ticket(conn: &mut PgConnection, ticket_hash: &[u8], now: i64) -> Result<Option<(User, Email)>, DomainError> {
	let ticket: Option<(Uuid, i64, i64, i64, Option<i64>)> =
		sqlx::query_as("SELECT user_id, token_version, password_set_at, expires_at, spent_at FROM signup_tickets WHERE ticket_hash = $1 FOR UPDATE")
			.bind(ticket_hash)
			.fetch_optional(&mut *conn)
			.await
			.map_err(repo_err)?;
	let Some((user_id, token_version, password_set_at, expires_at, spent_at)) = ticket else {
		return Ok(None);
	};
	if spent_at.is_some() || now >= expires_at {
		return Ok(None);
	}
	let user = UserId::from_raw(user_id);
	let email = email_of(conn, user).await?;
	lock_email(conn, &email).await?;
	let account = load_for_update(conn, user).await?;
	let password: Option<i64> = sqlx::query_scalar("SELECT updated_at FROM password_credentials WHERE user_id = $1 FOR UPDATE")
		.bind(user_id)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	// A takeover bumps `token_version` and drops the password; a "revoke all" bumps the
	// former and a new password moves the latter. After any of them, the browser that
	// signed up is no longer the one this account answers to. An address that moved
	// between the read and the lock is not the one the ticket's code went to.
	let live = i64::try_from(account.token_version()).is_ok_and(|v| v == token_version) && password == Some(password_set_at) && *account.email() == email;
	Ok(live.then_some((account, email)))
}

/// Spend a verification code and mark the account's address verified. The caller commits
/// whatever the outcome: a wrong guess must stay counted.
async fn verify_with_code(conn: &mut PgConnection, user: UserId, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError> {
	let email = email_of(conn, user).await?;
	lock_email(conn, &email).await?;
	let account = load_for_update(conn, user).await?;
	// Moved between the read and the lock: a code for this account went to the old address.
	if *account.email() != email {
		return Ok(Err(VerifyRefusal::Code(CodeRefusal::Missing)));
	}
	verify_locked(conn, account, &email, code, now).await
}

/// [`verify_with_code`] for a caller already holding `email`'s lock and `account`'s row,
/// with `account` on that address.
async fn verify_locked(conn: &mut PgConnection, mut account: User, email: &Email, code: &str, now: i64) -> Result<Result<User, VerifyRefusal>, DomainError> {
	if let Err(refusal) = redeem(conn, email, "verify", Some(account.id()), None, code, now).await? {
		return Ok(Err(VerifyRefusal::Code(refusal)));
	}
	if verified_holder(conn, email).await?.is_some_and(|holder| holder != account.id()) {
		return Ok(Err(VerifyRefusal::Taken));
	}
	account.verify_email();
	update_row(conn, &account).await?;
	Ok(Ok(account))
}

async fn write_password(conn: &mut PgConnection, user: UserId, phc: &str, now: i64) -> Result<(), DomainError> {
	sqlx::query(
		"INSERT INTO password_credentials (user_id, phc, updated_at) VALUES ($1, $2, $3) \
		 ON CONFLICT (user_id) DO UPDATE SET phc = EXCLUDED.phc, failed_attempts = 0, locked_until = NULL, updated_at = EXCLUDED.updated_at",
	)
	.bind(user.raw())
	.bind(phc)
	.bind(now)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn codes_are_six_digits_and_digests_are_bound_to_their_row() {
		for _ in 0..1000 {
			let code = six_digits();
			assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "{code}");
		}
		let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
		assert_ne!(digest(a, "123456"), digest(b, "123456"));
		assert_eq!(digest(a, "123456").len(), 32);
	}
}
