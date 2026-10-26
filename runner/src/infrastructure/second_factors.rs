//! Postgres adapter for second factors. Every write takes the account's
//! `second_factor_guard` row first, `FOR UPDATE`: it is the account's lock for everything
//! here, and the wrong-answer count it holds is read and written in the same transaction as
//! the answer it counts. A write that also moves the `users` row (a recovery, the owners'
//! reset) takes that row before the guard.

use async_trait::async_trait;
use domain::{error::DomainError, users::UserId};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::users::{drain_outbox, load_for_update, update_row};
use crate::{
	ports::{
		Attempt, Check, Confirmed, Enrolling, MAX_SECOND_FACTORS, Removed, SECOND_FACTOR_DAY_SECS, SECOND_FACTOR_ENROLMENT_TTL_SECS, SECOND_FACTOR_LOCK_SECS, SECOND_FACTOR_WINDOW_SECS,
		SECOND_FACTOR_WRONG_PER_DAY, SECOND_FACTOR_WRONG_PER_WINDOW, SealedFactor, SecondFactorRepository, SecondFactorRow, SecondFactors, SecurityEvent, Verdict,
	},
	second_factor::FactorKind,
};

pub struct PgSecondFactors {
	pool: PgPool,
}

impl PgSecondFactors {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

fn kind_of(raw: &str) -> Result<FactorKind, DomainError> {
	raw.parse()
		.map_err(|_| DomainError::Repository(format!("second_factors.kind {raw:?} is not a kind this build knows")))
}

#[derive(sqlx::FromRow)]
struct Guard {
	window_started_at: i64,
	window_wrong: i32,
	day_started_at: i64,
	day_wrong: i32,
	locked_until: Option<i64>,
}

/// The account's guard row, locked. Created on first use.
async fn guard(conn: &mut PgConnection, user: UserId, now: i64) -> Result<Guard, DomainError> {
	sqlx::query("INSERT INTO second_factor_guard (user_id, window_started_at, window_wrong, day_started_at, day_wrong) VALUES ($1, $2, 0, $2, 0) ON CONFLICT (user_id) DO NOTHING")
		.bind(user.raw())
		.bind(now)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	sqlx::query_as("SELECT window_started_at, window_wrong, day_started_at, day_wrong, locked_until FROM second_factor_guard WHERE user_id = $1 FOR UPDATE")
		.bind(user.raw())
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)
}

fn locked(g: &Guard, now: i64) -> Option<i64> {
	g.locked_until.filter(|until| *until > now)
}

/// Count one answer. A right one clears the short window and never the day.
async fn count(conn: &mut PgConnection, user: UserId, mut g: Guard, right: bool, now: i64) -> Result<(), DomainError> {
	if now - g.window_started_at >= SECOND_FACTOR_WINDOW_SECS {
		g.window_started_at = now;
		g.window_wrong = 0;
	}
	if now - g.day_started_at >= SECOND_FACTOR_DAY_SECS {
		g.day_started_at = now;
		g.day_wrong = 0;
	}
	if right {
		g.window_wrong = 0;
	} else {
		g.window_wrong += 1;
		g.day_wrong += 1;
		if g.day_wrong >= SECOND_FACTOR_WRONG_PER_DAY {
			g.locked_until = Some(g.day_started_at + SECOND_FACTOR_DAY_SECS);
		} else if g.window_wrong >= SECOND_FACTOR_WRONG_PER_WINDOW {
			g.locked_until = Some(now + SECOND_FACTOR_LOCK_SECS);
			g.window_started_at = now;
			g.window_wrong = 0;
		}
	}
	sqlx::query("UPDATE second_factor_guard SET window_started_at = $2, window_wrong = $3, day_started_at = $4, day_wrong = $5, locked_until = $6 WHERE user_id = $1")
		.bind(user.raw())
		.bind(g.window_started_at)
		.bind(g.window_wrong)
		.bind(g.day_started_at)
		.bind(g.day_wrong)
		.bind(g.locked_until)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

async fn confirmed_count(conn: &mut PgConnection, user: UserId) -> Result<i64, DomainError> {
	sqlx::query_scalar("SELECT count(*) FROM second_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL")
		.bind(user.raw())
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)
}

/// Queue the account's security notice. Every account holding a factor has a verified
/// address (enrolment demands it), so one without is refused rather than told nothing.
pub(super) async fn notice(conn: &mut PgConnection, user: UserId, event: SecurityEvent, label: Option<&str>, now: i64) -> Result<(), DomainError> {
	let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND email_verified")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	let email = email.ok_or_else(|| DomainError::Repository(format!("a second factor of {user} changed and the account has no verified address to tell")))?;
	let event: &'static str = event.into();
	sqlx::query("INSERT INTO notification_deliveries (kind, recipient, dedupe_key, payload) VALUES ('security_notice', $1, $2, $3)")
		.bind(email)
		.bind(format!("security_notice:{}", Uuid::new_v4()))
		.bind(serde_json::json!({ "event": event, "label": label, "at": now }))
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

async fn store_recovery(conn: &mut PgConnection, user: UserId, recovery: &[[u8; 32]], now: i64) -> Result<(), DomainError> {
	sqlx::query("DELETE FROM second_factor_recovery_codes WHERE user_id = $1")
		.bind(user.raw())
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	for digest in recovery {
		sqlx::query("INSERT INTO second_factor_recovery_codes (user_id, digest, created_at) VALUES ($1, $2, $3)")
			.bind(user.raw())
			.bind(digest.as_slice())
			.bind(now)
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}
	Ok(())
}

/// Every factor and recovery code of the account, gone. Takes the guard first, as every
/// writer here does; a caller holding the account's `users` row takes it before this.
pub(super) async fn wipe(conn: &mut PgConnection, user: UserId, now: i64) -> Result<(), DomainError> {
	guard(conn, user, now).await?;
	sqlx::query("DELETE FROM second_factors WHERE user_id = $1")
		.bind(user.raw())
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	store_recovery(conn, user, &[], now).await
}

#[derive(sqlx::FromRow)]
struct FactorRow {
	id: Uuid,
	kind: String,
	label: String,
	material: Vec<u8>,
}

impl FactorRow {
	fn sealed(&self) -> Result<SealedFactor, DomainError> {
		Ok(SealedFactor {
			id: self.id,
			kind: kind_of(&self.kind)?,
			material: self.material.clone(),
		})
	}
}

enum Checked {
	Held,
	Wrong,
	Malformed,
}

/// Run `check` against a locked row and count it.
async fn checked(conn: &mut PgConnection, user: UserId, g: Guard, row: &FactorRow, check: Check, now: i64) -> Result<Checked, DomainError> {
	let material = match check(&row.sealed()?)? {
		Verdict::Malformed => return Ok(Checked::Malformed),
		Verdict::Wrong => {
			count(conn, user, g, false, now).await?;
			return Ok(Checked::Wrong);
		}
		Verdict::Right(material) => material,
	};
	count(conn, user, g, true, now).await?;
	sqlx::query("UPDATE second_factors SET material = $2, last_used_at = $3 WHERE id = $1")
		.bind(row.id)
		.bind(material)
		.bind(now)
		.execute(&mut *conn)
		.await
		.map_err(repo_err)?;
	Ok(Checked::Held)
}

#[async_trait]
impl SecondFactorRepository for PgSecondFactors {
	async fn second_factors(&self, user: UserId) -> Result<SecondFactors, DomainError> {
		let rows: Vec<(Uuid, String, String, i64, Option<i64>)> =
			sqlx::query_as("SELECT id, kind, label, created_at, last_used_at FROM second_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL ORDER BY confirmed_at, id")
				.bind(user.raw())
				.fetch_all(&self.pool)
				.await
				.map_err(repo_err)?;
		let factors = rows
			.into_iter()
			.map(|(id, kind, label, created_at, last_used_at)| {
				Ok(SecondFactorRow {
					id,
					kind: kind_of(&kind)?,
					label,
					created_at,
					last_used_at,
				})
			})
			.collect::<Result<Vec<_>, DomainError>>()?;
		let recovery_codes_left: i64 = sqlx::query_scalar("SELECT count(*) FROM second_factor_recovery_codes WHERE user_id = $1 AND used_at IS NULL")
			.bind(user.raw())
			.fetch_one(&self.pool)
			.await
			.map_err(repo_err)?;
		Ok(SecondFactors { factors, recovery_codes_left })
	}

	async fn sealed_factors(&self, user: UserId) -> Result<Vec<SealedFactor>, DomainError> {
		let rows: Vec<FactorRow> = sqlx::query_as("SELECT id, kind, label, material FROM second_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL ORDER BY confirmed_at, id")
			.bind(user.raw())
			.fetch_all(&self.pool)
			.await
			.map_err(repo_err)?;
		rows.iter().map(FactorRow::sealed).collect()
	}

	async fn begin_enrolment(&self, user: UserId, factor: SealedFactor, label: &str, now: i64) -> Result<Enrolling, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		guard(&mut tx, user, now).await?;
		sqlx::query("DELETE FROM second_factors WHERE user_id = $1 AND confirmed_at IS NULL")
			.bind(user.raw())
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		if confirmed_count(&mut tx, user).await? >= MAX_SECOND_FACTORS {
			return Ok(Enrolling::Full);
		}
		let kind: &'static str = factor.kind.into();
		sqlx::query("INSERT INTO second_factors (id, user_id, kind, label, material, created_at) VALUES ($1, $2, $3, $4, $5, $6)")
			.bind(factor.id)
			.bind(user.raw())
			.bind(kind)
			.bind(label)
			.bind(factor.material)
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Enrolling::Begun)
	}

	async fn confirm_enrolment(&self, user: UserId, enrolment: Uuid, check: Check, recovery: Vec<[u8; 32]>, now: i64) -> Result<Attempt<Confirmed>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let g = guard(&mut tx, user, now).await?;
		if let Some(until) = locked(&g, now) {
			return Ok(Attempt::Locked { until });
		}
		let row: Option<FactorRow> =
			sqlx::query_as("SELECT id, kind, label, material FROM second_factors WHERE id = $1 AND user_id = $2 AND confirmed_at IS NULL AND created_at > $3 FOR UPDATE")
				.bind(enrolment)
				.bind(user.raw())
				.bind(now - SECOND_FACTOR_ENROLMENT_TTL_SECS)
				.fetch_optional(&mut *tx)
				.await
				.map_err(repo_err)?;
		let Some(row) = row else {
			return Ok(Attempt::Unknown);
		};
		match checked(&mut tx, user, g, &row, check, now).await? {
			Checked::Held => {}
			Checked::Wrong => {
				tx.commit().await.map_err(repo_err)?;
				return Ok(Attempt::Wrong);
			}
			Checked::Malformed => return Ok(Attempt::Malformed),
		}
		// `begin_enrolment` keeps one enrolment per account and checked the cap under this
		// same lock, so no other confirmation can have landed since.
		let first = confirmed_count(&mut tx, user).await? == 0;
		sqlx::query("UPDATE second_factors SET confirmed_at = $2 WHERE id = $1")
			.bind(row.id)
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		if first {
			store_recovery(&mut tx, user, &recovery, now).await?;
		}
		notice(&mut tx, user, SecurityEvent::FactorAdded, Some(&row.label), now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Attempt::Accepted(Confirmed { first }))
	}

	async fn attempt(&self, user: UserId, factor: Uuid, check: Check, now: i64) -> Result<Attempt<()>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let g = guard(&mut tx, user, now).await?;
		if let Some(until) = locked(&g, now) {
			return Ok(Attempt::Locked { until });
		}
		let row: Option<FactorRow> = sqlx::query_as("SELECT id, kind, label, material FROM second_factors WHERE id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL FOR UPDATE")
			.bind(factor)
			.bind(user.raw())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		let Some(row) = row else {
			return Ok(Attempt::Unknown);
		};
		let outcome = match checked(&mut tx, user, g, &row, check, now).await? {
			Checked::Held => Attempt::Accepted(()),
			Checked::Wrong => Attempt::Wrong,
			Checked::Malformed => return Ok(Attempt::Malformed),
		};
		tx.commit().await.map_err(repo_err)?;
		Ok(outcome)
	}

	async fn remove(&self, user: UserId, factor: Uuid, now: i64) -> Result<Option<Removed>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		guard(&mut tx, user, now).await?;
		let label: Option<String> = sqlx::query_scalar("DELETE FROM second_factors WHERE id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL RETURNING label")
			.bind(factor)
			.bind(user.raw())
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		let Some(label) = label else {
			return Ok(None);
		};
		let remaining = confirmed_count(&mut tx, user).await?;
		if remaining == 0 {
			store_recovery(&mut tx, user, &[], now).await?;
		}
		notice(&mut tx, user, SecurityEvent::FactorRemoved, Some(&label), now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Some(Removed { remaining }))
	}

	async fn replace_recovery_codes(&self, user: UserId, recovery: Vec<[u8; 32]>, now: i64) -> Result<bool, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		guard(&mut tx, user, now).await?;
		if confirmed_count(&mut tx, user).await? == 0 {
			return Ok(false);
		}
		store_recovery(&mut tx, user, &recovery, now).await?;
		notice(&mut tx, user, SecurityEvent::RecoveryCodesReplaced, None, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(true)
	}

	async fn recover(&self, user: UserId, code: [u8; 32], now: i64) -> Result<Attempt<()>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		// The `users` row before the guard: the owners' reset (`people::apply`) holds it
		// while it wipes, and the two must not wait on each other.
		let mut account = load_for_update(&mut tx, user).await?;
		let g = guard(&mut tx, user, now).await?;
		if let Some(until) = locked(&g, now) {
			return Ok(Attempt::Locked { until });
		}
		let spent = sqlx::query("UPDATE second_factor_recovery_codes SET used_at = $3 WHERE user_id = $1 AND digest = $2 AND used_at IS NULL")
			.bind(user.raw())
			.bind(code.as_slice())
			.bind(now)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?
			.rows_affected()
			== 1;
		count(&mut tx, user, g, spent, now).await?;
		if !spent {
			tx.commit().await.map_err(repo_err)?;
			return Ok(Attempt::Wrong);
		}
		wipe(&mut tx, user, now).await?;
		account.revoke_tokens();
		update_row(&mut tx, &account).await?;
		drain_outbox(&mut tx, &mut account).await?;
		notice(&mut tx, user, SecurityEvent::Recovered, None, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Attempt::Accepted(()))
	}
}
