//! Postgres adapter for approvals (`approvals`, `approval_voters`, `approval_events`;
//! migration 0036, `docs/SCOPES-AND-APPROVALS.md` §5).
//!
//! Every write is ONE transaction that holds the proposal row `FOR UPDATE`, applies the
//! domain transition and appends its history row beside it, so a rolled-back act takes
//! its audit row with it. A write that finds an open proposal past its deadline writes
//! the expiry and commits it even when the act it was asked for is then refused: the
//! expiry is a fact, and the refusal is about it.
//!
//! Opening is serialised per proposer namespace by a transaction-scoped advisory lock: the
//! rolling 24h window sums every live proposal of a (kind, scope) and the live cap counts
//! the namespace's, and two proposals opened side by side must see each other or a batch
//! passes under a limit it exceeds together. A kind belongs to one namespace, so the one
//! lock covers both. Locks are then taken in the plane's order: `users` (the owner roster,
//! `FOR SHARE`) before `tenants`.
//!
//! Every instant is the DATABASE's (`clock_timestamp()`, read once the locks an act needs
//! are held), never a replica's clock: deadlines decided by several replicas must be
//! decided on one clock.

use std::{
	collections::HashMap,
	sync::{
		Arc,
		atomic::{AtomicI64, Ordering},
	},
};

use async_trait::async_trait;
use domain::{
	approvals::{
		self, Action, Decision, EXECUTION_WINDOW_SECS, Field, FieldValue, MAX_LIVE_PER_PROPOSER, MAX_TTL_SECS, Outcome, PLATFORM_DELAY_SECS, PLATFORM_MIN_ROSTER, PLATFORM_QUORUM_BPS,
		PULL_MARGIN_SECS, PlatformPolicy, ROLLING_WINDOW_SECS, ScopePolicy, Vote, Voter,
	},
	error::DomainError,
	scope_catalog::{ApprovalKind, ApprovalLevel},
	scopes::{ROOT, ScopeState},
	users::UserId,
};
use sqlx::{PgConnection, PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use super::{
	email::templates::{ApprovalMail, ApprovalMailField, ApprovalMailValue, ApprovalNote, NoteAuthor},
	grants::{ApprovedGrant, grant_by_approval, lock_accounts},
	notifications::{enqueue_governance_mail, upsert_subscriber},
	scope_catalogs,
	users::{Named, account_named},
};
use crate::ports::{
	ApprovalActor, ApprovalFilter, ApprovalPerson, ApprovalRecord, ApprovalRepository, ApprovalViewer, GovernanceMailQueued, NewApproval, PersonRef, Proposed, ProvenInitiator,
};

fn repo_err(err: sqlx::Error) -> DomainError {
	DomainError::Repository(err.to_string())
}

const COLUMNS: &str = "a.id, a.kind, a.proposer, a.scope, a.level, a.escalated_by, a.state, a.subject_ref, a.fields, a.payload_hash, \
	a.requested_by, rb.auth_subject AS rb_subject, rb.email AS rb_email, a.reason, a.threshold, a.policy_version, a.delay_secs, \
	a.created_at, a.expires_at, a.passed_at, a.executable_at, a.decided_at, a.vetoed_by, vb.auth_subject AS vb_subject, vb.email AS vb_email, \
	a.veto_reason, a.void_reason, a.outcome, a.outcome_detail, a.requested_by_client, a.version, a.action, a.requested_by_proven";
const FROM: &str = " FROM approvals a LEFT JOIN users rb ON rb.id = a.requested_by LEFT JOIN users vb ON vb.id = a.vetoed_by";

fn level_str(level: ApprovalLevel) -> &'static str {
	match level {
		ApprovalLevel::Platform => "platform",
		ApprovalLevel::Scope => "scope",
	}
}

fn level_of(raw: &str) -> Result<ApprovalLevel, DomainError> {
	match raw {
		"platform" => Ok(ApprovalLevel::Platform),
		"scope" => Ok(ApprovalLevel::Scope),
		other => Err(DomainError::Repository(format!("unknown approval level `{other}`"))),
	}
}

fn unsigned(value: i64, column: &str) -> Result<u64, DomainError> {
	u64::try_from(value).map_err(|_| DomainError::Repository(format!("approvals.{column} is negative")))
}

async fn advisory_lock(conn: &mut PgConnection, key: &str) -> Result<(), DomainError> {
	sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
		.bind(key)
		.execute(conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

/// Rows of `COLUMNS` as records, with their rosters read in one query.
async fn records_of(conn: &mut PgConnection, rows: Vec<PgRow>, as_of: i64) -> Result<Vec<ApprovalRecord>, DomainError> {
	let ids: Vec<Uuid> = rows.iter().map(|r| r.try_get("id")).collect::<Result<_, _>>().map_err(repo_err)?;
	let voter_rows = sqlx::query(
		"SELECT v.approval_id, v.user_id, v.vote, v.voted_at, u.auth_subject, u.email FROM approval_voters v JOIN users u ON u.id = v.user_id \
		 WHERE v.approval_id = ANY($1) ORDER BY v.approval_id, v.user_id",
	)
	.bind(&ids)
	.fetch_all(conn)
	.await
	.map_err(repo_err)?;
	let mut rosters: HashMap<Uuid, Vec<(Voter, ApprovalPerson)>> = HashMap::new();
	for row in voter_rows {
		let approval: Uuid = row.try_get("approval_id").map_err(repo_err)?;
		let voter = Voter {
			user_id: UserId::from_raw(row.try_get("user_id").map_err(repo_err)?),
			vote: Vote::parse(row.try_get("vote").map_err(repo_err)?)?,
			voted_at: row.try_get::<Option<i64>, _>("voted_at").map_err(repo_err)?.unwrap_or(0),
		};
		let person = ApprovalPerson {
			auth_subject: row.try_get("auth_subject").map_err(repo_err)?,
			email: row.try_get::<Option<String>, _>("email").map_err(repo_err)?.unwrap_or_default(),
		};
		rosters.entry(approval).or_default().push((voter, person));
	}
	rows.iter()
		.map(|row| {
			let id: Uuid = row.try_get("id").map_err(repo_err)?;
			let (voters, people): (Vec<Voter>, Vec<ApprovalPerson>) = rosters.remove(&id).unwrap_or_default().into_iter().unzip();
			record_of(row, voters, people, as_of)
		})
		.collect()
}

fn person(row: &PgRow, subject: &str, email: &str) -> Result<Option<ApprovalPerson>, DomainError> {
	let subject: Option<String> = row.try_get(subject).map_err(repo_err)?;
	let email: Option<String> = row.try_get(email).map_err(repo_err)?;
	Ok(subject.map(|auth_subject| ApprovalPerson {
		auth_subject,
		email: email.unwrap_or_default(),
	}))
}

fn record_of(row: &PgRow, voters: Vec<Voter>, people: Vec<ApprovalPerson>, as_of: i64) -> Result<ApprovalRecord, DomainError> {
	let get_i64 = |column: &str| row.try_get::<i64, _>(column).map_err(repo_err);
	let get_opt = |column: &str| row.try_get::<Option<i64>, _>(column).map_err(repo_err);
	let fields: Vec<Field> = serde_json::from_value(row.try_get("fields").map_err(repo_err)?).map_err(|e| DomainError::Repository(format!("stored approval fields are unreadable: {e}")))?;
	let requested_by = match (row.try_get::<Option<Uuid>, _>("requested_by").map_err(repo_err)?, person(row, "rb_subject", "rb_email")?) {
		(Some(id), Some(who)) => Some((UserId::from_raw(id), who)),
		_ => None,
	};
	let outcome = row.try_get::<Option<String>, _>("outcome").map_err(repo_err)?.map(|o| Outcome::parse(&o)).transpose()?;
	let threshold = u32::try_from(row.try_get::<i32, _>("threshold").map_err(repo_err)?).map_err(|_| DomainError::Repository("approvals.threshold is negative".into()))?;
	Ok(ApprovalRecord {
		id: row.try_get("id").map_err(repo_err)?,
		kind: row.try_get("kind").map_err(repo_err)?,
		proposer: row.try_get("proposer").map_err(repo_err)?,
		scope: row.try_get("scope").map_err(repo_err)?,
		level: level_of(row.try_get("level").map_err(repo_err)?)?,
		escalated_by: row.try_get("escalated_by").map_err(repo_err)?,
		subject_ref: row.try_get("subject_ref").map_err(repo_err)?,
		fields,
		payload_hash: row.try_get("payload_hash").map_err(repo_err)?,
		requested_by,
		reason: row.try_get("reason").map_err(repo_err)?,
		voters: people,
		vetoed_by: person(row, "vb_subject", "vb_email")?,
		policy_version: unsigned(get_i64("policy_version")?, "policy_version")?,
		created_at: get_i64("created_at")?,
		requested_by_client: row.try_get("requested_by_client").map_err(repo_err)?,
		action: row
			.try_get::<Option<serde_json::Value>, _>("action")
			.map_err(repo_err)?
			.map(serde_json::from_value)
			.transpose()
			.map_err(|e| DomainError::Repository(format!("stored approval action is unreadable: {e}")))?,
		requested_by_proven: row.try_get("requested_by_proven").map_err(repo_err)?,
		as_of,
		decision: Decision {
			state: approvals::ApprovalState::parse(row.try_get("state").map_err(repo_err)?)?,
			threshold,
			voters,
			delay_secs: get_i64("delay_secs")?,
			expires_at: get_i64("expires_at")?,
			passed_at: get_opt("passed_at")?,
			executable_at: get_opt("executable_at")?,
			decided_at: get_opt("decided_at")?,
			vetoed_by: row.try_get::<Option<Uuid>, _>("vetoed_by").map_err(repo_err)?.map(UserId::from_raw),
			veto_reason: row.try_get("veto_reason").map_err(repo_err)?,
			void_reason: row.try_get("void_reason").map_err(repo_err)?,
			outcome,
			outcome_detail: row.try_get("outcome_detail").map_err(repo_err)?,
			version: unsigned(get_i64("version")?, "version")?,
			pending: Vec::new(),
		},
	})
}

async fn load(conn: &mut PgConnection, id: Uuid, for_update: bool, as_of: i64) -> Result<Option<ApprovalRecord>, DomainError> {
	let lock = if for_update { " FOR UPDATE OF a" } else { "" };
	let row = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS}{FROM} WHERE a.id = $1{lock}")))
		.bind(id)
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	let Some(row) = row else { return Ok(None) };
	Ok(records_of(conn, vec![row], as_of).await?.pop())
}

fn not_found(id: Uuid) -> DomainError {
	DomainError::NotFound {
		entity: "approval",
		id: id.to_string(),
	}
}

/// Write what the decision moved, and one history row per transition it drained.
async fn persist(conn: &mut PgConnection, id: Uuid, decision: &mut Decision, actor: Option<ApprovalActor<'_>>, detail: &serde_json::Value, now: i64) -> Result<(), DomainError> {
	let version = i64::try_from(decision.version).map_err(|_| DomainError::Repository("approval version overflows".into()))?;
	sqlx::query(
		"UPDATE approvals SET state = $2, passed_at = $3, executable_at = $4, decided_at = $5, vetoed_by = $6, veto_reason = $7, void_reason = $8, \
		 outcome = $9, outcome_detail = $10, version = $11 WHERE id = $1",
	)
	.bind(id)
	.bind(decision.state.as_str())
	.bind(decision.passed_at)
	.bind(decision.executable_at)
	.bind(decision.decided_at)
	.bind(decision.vetoed_by.map(|u| u.raw()))
	.bind(&decision.veto_reason)
	.bind(&decision.void_reason)
	.bind(decision.outcome.map(Outcome::as_str))
	.bind(&decision.outcome_detail)
	.bind(version)
	.execute(&mut *conn)
	.await
	.map_err(repo_err)?;
	for voter in decision.voters.iter().filter(|v| v.vote != Vote::Pending) {
		sqlx::query("UPDATE approval_voters SET vote = $3, voted_at = $4 WHERE approval_id = $1 AND user_id = $2 AND vote = 'pending'")
			.bind(id)
			.bind(voter.user_id.raw())
			.bind(voter.vote.as_str())
			.bind(voter.voted_at)
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}
	write_events(conn, id, decision, actor, detail, now).await
}

async fn write_events(conn: &mut PgConnection, id: Uuid, decision: &mut Decision, actor: Option<ApprovalActor<'_>>, detail: &serde_json::Value, now: i64) -> Result<(), DomainError> {
	let version = i64::try_from(decision.version).map_err(|_| DomainError::Repository("approval version overflows".into()))?;
	for event in std::mem::take(&mut decision.pending) {
		// Nobody performs an expiry or a lapse: it is written by whichever act found it due.
		let (person, client, detail) = match (event, actor) {
			(approvals::ApprovalEvent::Expired | approvals::ApprovalEvent::Lapsed, _) | (_, None) => (None, String::new(), serde_json::json!({})),
			(_, Some(ApprovalActor::Person(user))) => (Some(user.raw()), String::new(), detail.clone()),
			(_, Some(ApprovalActor::Service(client))) => (None, client.to_owned(), detail.clone()),
		};
		sqlx::query("INSERT INTO approval_events (approval_id, event, actor_user_id, actor_client, version, detail, at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
			.bind(id)
			.bind(event.as_str())
			.bind(person)
			.bind(client)
			.bind(version)
			.bind(detail)
			.bind(now)
			.execute(&mut *conn)
			.await
			.map_err(repo_err)?;
	}
	Ok(())
}

/// Commit what `act` moved — and a due expiry found on the way even when `act` was
/// refused — then answer the record as it now stands, or the refusal.
async fn finish(
	mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
	mut record: ApprovalRecord,
	result: Result<(), DomainError>,
	actor: ApprovalActor<'_>,
	detail: serde_json::Value,
	now: i64,
) -> Result<ApprovalRecord, DomainError> {
	let result = if record.decision.pending.is_empty() {
		// Nothing moved: a refusal rolls back, a no-op answers what is stored.
		result?;
		Ok(())
	} else {
		persist(&mut tx, record.id, &mut record.decision, Some(actor), &detail, now).await?;
		result
	};
	let stored = load(&mut tx, record.id, false, now).await?.ok_or_else(|| not_found(record.id))?;
	tx.commit().await.map_err(repo_err)?;
	result.map(|()| stored)
}

/// The persisted owners: the platform roster. Break-glass seats nobody. Read without a
/// lock: a seat that moves after the roster is frozen is caught where it matters, at the
/// vote (`holds_seat`, `unseated`), and holding every owner row for each proposal would
/// queue every role change behind every open.
/// Returns the roster and, apart, the owners who can decide now (active): a held owner
/// is on the roster with no say, and a floor counts only those who have one.
async fn owners(conn: &mut PgConnection) -> Result<(Vec<UserId>, Vec<UserId>), DomainError> {
	let rows: Vec<(Uuid, bool)> = sqlx::query_as("SELECT id, status = 'active' FROM users WHERE role = 'owner' ORDER BY id")
		.fetch_all(conn)
		.await
		.map_err(repo_err)?;
	let active = rows.iter().filter(|(_, active)| *active).map(|(id, _)| UserId::from_raw(*id)).collect();
	Ok((rows.into_iter().map(|(id, _)| UserId::from_raw(id)).collect(), active))
}

/// The active holders of `<namespace>:admin`: a scope's roster.
async fn scope_admins(conn: &mut PgConnection, namespace: &str) -> Result<Vec<UserId>, DomainError> {
	let ids: Vec<Uuid> = sqlx::query_scalar(
		"SELECT DISTINCT u.id FROM grants g JOIN users u ON u.id = g.user_id \
		 WHERE g.namespace = $1 AND g.target = $1 || ':admin' AND g.revoked_at IS NULL AND u.status = 'active' ORDER BY u.id",
	)
	.bind(namespace)
	.fetch_all(conn)
	.await
	.map_err(repo_err)?;
	Ok(ids.into_iter().map(UserId::from_raw).collect())
}

/// Whether `user` still holds the seat `record`'s roster was drawn from. The roster is
/// frozen so that it cannot be stuffed; it does not keep a removed admin's say — removing
/// one is the containment step and must bite at once (§5.6).
async fn holds_seat(conn: &mut PgConnection, record: &ApprovalRecord, user: UserId) -> Result<bool, DomainError> {
	let query = match record.level {
		ApprovalLevel::Platform => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 'owner' AND status = 'active')").bind(user.raw()),
		ApprovalLevel::Scope => sqlx::query_scalar(
			"SELECT EXISTS (SELECT 1 FROM grants g JOIN tenants t ON t.namespace = g.namespace JOIN users u ON u.id = g.user_id \
			 WHERE t.id = $2 AND g.user_id = $1 AND g.target = t.namespace || ':admin' AND g.revoked_at IS NULL AND u.status = 'active')",
		)
		.bind(user.raw())
		.bind(record.scope.clone()),
	};
	query.fetch_one(conn).await.map_err(repo_err)
}

async fn user_by_subject(conn: &mut PgConnection, subject: &str) -> Result<Option<Uuid>, DomainError> {
	sqlx::query_scalar("SELECT id FROM users WHERE auth_subject = $1")
		.bind(subject)
		.fetch_optional(conn)
		.await
		.map_err(repo_err)
}

/// The SQLSTATE the store's pause raises (migration 0038, `approvals_platform_pause`).
const PAUSE_SQLSTATE: &str = "EVA01";

/// A token proves who asked only if it is the named person's (`requested_by`, resolved),
/// still standing as it was when the token was minted.
async fn check_proof(conn: &mut PgConnection, proven: &ProvenInitiator, requested_by: Option<Uuid>) -> Result<(), DomainError> {
	if requested_by != Some(proven.user.raw()) {
		return Err(DomainError::Forbidden("the user token is not requested_by's".into()));
	}
	let standing: Option<(String, i64)> = sqlx::query_as("SELECT status, token_version FROM users WHERE id = $1")
		.bind(proven.user.raw())
		.fetch_optional(conn)
		.await
		.map_err(repo_err)?;
	let live = standing.is_some_and(|(status, floor)| status == "active" && u64::try_from(floor).is_ok_and(|floor| proven.token_version >= floor));
	if !live {
		return Err(DomainError::Forbidden("the user token no longer speaks for an active account".into()));
	}
	Ok(())
}

/// Spend a proof: one token proves one request. Spent in the transaction that opens the
/// proposal, so a refused open spends nothing and a committed one can never be repeated
/// under another `dedupe_key`.
async fn spend_proof(conn: &mut PgConnection, proven: &ProvenInitiator, approval: Uuid, now: i64) -> Result<(), DomainError> {
	let spent: Option<String> =
		sqlx::query_scalar("INSERT INTO approval_initiator_proofs (token_digest, approval_id, at) VALUES ($1, $2, $3) ON CONFLICT (token_digest) DO NOTHING RETURNING token_digest")
			.bind(&proven.token_digest)
			.bind(approval)
			.bind(now)
			.fetch_optional(conn)
			.await
			.map_err(repo_err)?;
	if spent.is_none() {
		return Err(DomainError::Precondition("this proof was already spent: mint a token for each request".into()));
	}
	Ok(())
}

/// Tell the person a money decision names, proven by their token and so kept off its
/// roster, that it was opened in their name: if they did not ask for it, the one thing
/// that stops it is their veto. Platform words only — no link, no code, nothing the service
/// wrote — filed under money movement like a consent's trace, and written whatever they
/// follow: nobody subscribes to being named in a decision about money.
async fn tell_initiator(conn: &mut PgConnection, user: UserId, approval: Uuid, scope: &str, now: i64) -> Result<(), DomainError> {
	let (email, verified): (Option<String>, bool) = sqlx::query_as("SELECT email, email_verified FROM users WHERE id = $1")
		.bind(user.raw())
		.fetch_one(&mut *conn)
		.await
		.map_err(repo_err)?;
	let subscriber = upsert_subscriber(conn, user.raw(), email.as_deref().unwrap_or_default(), verified).await?;
	sqlx::query(
		"INSERT INTO notifications (subscriber_id, topic, kind, title, body, dedupe_key, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
		 ON CONFLICT (subscriber_id, dedupe_key) DO NOTHING",
	)
	.bind(subscriber.id)
	.bind("account:money-movement")
	.bind("approval_opened_in_your_name")
	.bind("A money decision was opened in your name")
	.bind(format!(
		"A decision in scope {scope} names you as the person who asked for it, with your session as proof. \
		 The other platform owners decide it without you. If you did not ask for it, veto it in the approvals console."
	))
	.bind(format!("approval:{approval}"))
	.bind(now)
	.execute(conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}

const MAIL_REQUEST: &str = "approval_request";
const MAIL_OUTCOME: &str = "approval_outcome";

/// The typed mail about `record`, labelled from `kind`. A kind its catalog no longer
/// carries falls back to its name and the field keys: the mail still says what was
/// decided, only less prettily.
async fn mail_of(conn: &mut PgConnection, record: &ApprovalRecord, kind: Option<&ApprovalKind>) -> Result<ApprovalMail, DomainError> {
	let mut fields = Vec::with_capacity(record.fields.len());
	for field in &record.fields {
		let label = kind
			.and_then(|k| k.fields.iter().find(|spec| spec.key == field.key))
			.map_or_else(|| field.key.clone(), |spec| spec.label.clone());
		let value = match &field.value {
			FieldValue::Text(text) => ApprovalMailValue::Text(text.clone()),
			FieldValue::Amount(amount) => ApprovalMailValue::Amount {
				value: amount.value.clone(),
				currency: amount.currency.clone(),
			},
			FieldValue::Bps(bps) => ApprovalMailValue::Bps(*bps),
			FieldValue::Flag(flag) => ApprovalMailValue::Flag(*flag),
			FieldValue::Timestamp(ts) => ApprovalMailValue::Timestamp(*ts),
			FieldValue::Count(count) => ApprovalMailValue::Count(*count),
			// A person is shown by address: an `auth_subject` means nothing to a reader.
			FieldValue::User(subject) => {
				let email: Option<Option<String>> = sqlx::query_scalar("SELECT email FROM users WHERE auth_subject = $1")
					.bind(subject)
					.fetch_optional(&mut *conn)
					.await
					.map_err(repo_err)?;
				ApprovalMailValue::User(email.flatten().unwrap_or_else(|| "an account with no address".to_owned()))
			}
		};
		fields.push(ApprovalMailField { label, value });
	}
	Ok(ApprovalMail {
		approval_id: record.id.to_string(),
		kind: record.kind.clone(),
		kind_label: kind.map_or_else(|| record.kind.clone(), |k| k.label.clone()),
		proposer: record.proposer.clone(),
		scope: record.scope.clone(),
		level: record.level,
		requested_by: record.requested_by.as_ref().map(|(_, who)| who.email.clone()).unwrap_or_default(),
		reason: record.reason.clone(),
		fields,
		threshold: record.decision.threshold,
		roster_size: u32::try_from(record.decision.voters.len()).map_err(|_| DomainError::Repository("roster overflows".into()))?,
		expires_at: record.decision.expires_at,
		outcome: None,
		note: None,
	})
}

/// Queue one approval mail; a key some other mail already holds is logged, not fatal —
/// the decision stands whether or not one mail could be queued.
async fn queue_mail(conn: &mut PgConnection, user: Uuid, email: &str, kind: &str, dedupe_key: &str, payload: &serde_json::Value) -> Result<(), DomainError> {
	// `true` is the identity record's flag, read by the caller's filter: only a verified
	// address is mailed, and the subscriber row must say what the record says (#65).
	let subscriber = upsert_subscriber(conn, user, email, true).await?;
	match enqueue_governance_mail(conn, subscriber.id, email, kind, dedupe_key, payload).await? {
		GovernanceMailQueued::Inserted | GovernanceMailQueued::SameMail => {}
		GovernanceMailQueued::Foreign => tracing::error!(dedupe_key, kind, "an approval mail's dedupe key names another mail; not queued"),
	}
	Ok(())
}

/// The request to every roster member who can act on it: an active account at a VERIFIED
/// address (§5.5) — an unproven address hands the seat's say to whoever holds the mailbox,
/// and a held owner has no vote to cast. In the opening transaction, so a proposal never
/// exists without its mail queued, and keyed per proposal and member, so it is queued once.
async fn mail_roster(conn: &mut PgConnection, record: &ApprovalRecord, kind: &ApprovalKind) -> Result<(), DomainError> {
	let payload = serde_json::to_value(mail_of(conn, record, Some(kind)).await?).map_err(|e| DomainError::Repository(format!("approval mail does not encode: {e}")))?;
	let roster: Vec<Uuid> = record.decision.voters.iter().map(|v| v.user_id.raw()).collect();
	let reachable: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, email FROM users WHERE id = ANY($1) AND status = 'active' AND email_verified AND email IS NOT NULL ORDER BY id")
		.bind(&roster)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
	for (user, email) in reachable {
		queue_mail(conn, user, &email, MAIL_REQUEST, &format!("{MAIL_REQUEST}:{}:{user}", record.id), &payload).await?;
	}
	Ok(())
}

/// Whose words close the outcome mail, if any.
fn note_of(record: &ApprovalRecord, state: approvals::ApprovalState) -> Option<ApprovalNote> {
	use approvals::ApprovalState as S;
	let decision = &record.decision;
	let (by, text) = match state {
		S::Vetoed => (NoteAuthor::Vetoer, decision.veto_reason.clone()),
		S::Executed | S::ExecutionFailed => (NoteAuthor::Proposer, decision.outcome_detail.clone()),
		// A proposer's VOID report carries its own words; every other void is this plane's.
		S::Void if decision.outcome == Some(Outcome::Void) => (NoteAuthor::Proposer, decision.outcome_detail.clone()),
		// Stored `passed`: a lapse projected, not yet written, so the reason is not stored.
		S::Void if decision.state == S::Passed => (NoteAuthor::Platform, approvals::LAPSED.to_owned()),
		S::Void => (NoteAuthor::Platform, decision.void_reason.clone()),
		S::Open | S::Passed | S::Rejected | S::Expired | S::Cancelled => return None,
	};
	(!text.is_empty()).then_some(ApprovalNote { by, text })
}

/// The outcome to the person the proposal names as `requested_by`, under the same rule as
/// the request: an active account at a verified address. Keyed per proposal and state, so
/// "approved" and then "carried out" are two mails and neither is queued twice.
async fn mail_outcome(conn: &mut PgConnection, record: &ApprovalRecord, state: approvals::ApprovalState, kind: Option<&ApprovalKind>) -> Result<(), DomainError> {
	let Some((user, _)) = &record.requested_by else { return Ok(()) };
	let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND status = 'active' AND email_verified AND email IS NOT NULL")
		.bind(user.raw())
		.fetch_optional(&mut *conn)
		.await
		.map_err(repo_err)?;
	let Some(email) = email else { return Ok(()) };
	let mut mail = mail_of(conn, record, kind).await?;
	mail.outcome = Some(state.as_str().to_owned());
	mail.note = note_of(record, state);
	let payload = serde_json::to_value(mail).map_err(|e| DomainError::Repository(format!("approval mail does not encode: {e}")))?;
	queue_mail(conn, user.raw(), &email, MAIL_OUTCOME, &format!("{MAIL_OUTCOME}:{}:{}", record.id, state.as_str()), &payload).await
}

/// A persisted, active owner: the seat that vetoes anything (decided) and sees everything.
async fn is_owner(conn: &mut PgConnection, user: UserId) -> Result<bool, DomainError> {
	sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 'owner' AND status = 'active')")
		.bind(user.raw())
		.fetch_one(conn)
		.await
		.map_err(repo_err)
}

/// Where instants come from: the database's clock, or — for a suite that has to cross a
/// 72-hour deadline without waiting for it — a value the suite moves.
#[derive(Clone)]
enum Clock {
	Database,
	Fixed(Arc<AtomicI64>),
}

pub struct PgApprovals {
	pool: PgPool,
	clock: Clock,
}

impl PgApprovals {
	pub fn new(pool: PgPool) -> Self {
		Self { pool, clock: Clock::Database }
	}

	/// Every instant read from `now` instead of the database. For suites only: an
	/// integration test is another crate, so `cfg(test)` cannot hide it, and a feature
	/// would put a second clock one flag away from production.
	#[doc(hidden)]
	pub fn with_fixed_time(pool: PgPool, now: Arc<AtomicI64>) -> Self {
		Self { pool, clock: Clock::Fixed(now) }
	}

	/// The instant on `conn`: inside a transaction, the transaction's own `now()`, so every
	/// comparison it makes is against one value.
	async fn instant(&self, conn: &mut PgConnection) -> Result<i64, DomainError> {
		match &self.clock {
			// `clock_timestamp()`, not `now()`: `now()` is when the transaction began, which
			// can be long before a lock it then waited for was granted.
			Clock::Database => sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT")
				.fetch_one(conn)
				.await
				.map_err(repo_err),
			Clock::Fixed(now) => Ok(now.load(Ordering::SeqCst)),
		}
	}

	async fn begin_locked(&self, id: Uuid) -> Result<(sqlx::Transaction<'_, sqlx::Postgres>, ApprovalRecord, i64), DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let mut record = load(&mut tx, id, true, 0).await?.ok_or_else(|| not_found(id))?;
		// Read after the row lock is held, so a deadline is judged at the instant the act
		// takes effect, not before it waited.
		let now = self.instant(&mut tx).await?;
		record.as_of = now;
		Ok((tx, record, now))
	}
}

#[async_trait]
impl ApprovalRepository for PgApprovals {
	async fn now(&self) -> Result<i64, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		self.instant(&mut conn).await
	}

	async fn propose(&self, new: NewApproval) -> Result<Proposed, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		advisory_lock(&mut tx, &format!("approval_proposer:{}", new.proposer)).await?;
		let now = self.instant(&mut tx).await?;
		let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM approvals WHERE proposer = $1 AND dedupe_key = $2")
			.bind(&new.proposer)
			.bind(&new.dedupe_key)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(id) = existing {
			let stored = load(&mut tx, id, false, now).await?.ok_or_else(|| not_found(id))?;
			// A retry with a token answers as the first call would have: a token that is not
			// the named person's is refused here too, rather than waved through because the
			// proposal exists. Nothing is spent — the first call spent its own proof.
			if let Some(proven) = &new.proven {
				check_proof(&mut tx, proven, stored.requested_by.as_ref().map(|(user, _)| user.raw())).await?;
			}
			let same = stored.kind == new.kind.name
				&& stored.scope == new.scope
				&& stored.subject_ref == new.subject_ref
				&& stored.payload_hash == new.payload_hash
				&& stored.reason == new.reason
				&& stored.requested_by.as_ref().map(|(_, p)| p.auth_subject.as_str()) == new.requested_by.as_deref();
			return if same {
				Ok(Proposed::Existing(stored))
			} else {
				Err(DomainError::Conflict(format!("dedupe_key already names proposal {id}, with different content")))
			};
		}
		let live: i64 = sqlx::query_scalar(
			"SELECT count(*) FROM approvals WHERE proposer = $1 AND scope = $4 \
			 AND ((state = 'open' AND expires_at > $2) OR (state = 'passed' AND executable_at + $3 > $2))",
		)
		.bind(&new.proposer)
		.bind(now)
		.bind(EXECUTION_WINDOW_SECS)
		.bind(&new.scope)
		.fetch_one(&mut *tx)
		.await
		.map_err(repo_err)?;
		if live >= MAX_LIVE_PER_PROPOSER {
			return Ok(Proposed::Saturated);
		}

		// `users` before `tenants`, the plane's order, even when this proposal ends up at
		// the scope.
		let (owners, active_owners) = owners(&mut tx).await?;
		let in_root = new.scope == ROOT;
		let namespace = if in_root {
			None
		} else {
			let row: Option<(String, String)> = sqlx::query_as("SELECT namespace, state FROM tenants WHERE id = $1 FOR SHARE")
				.bind(&new.scope)
				.fetch_optional(&mut *tx)
				.await
				.map_err(repo_err)?;
			let Some((namespace, state)) = row else {
				return Err(DomainError::Validation(format!("unknown scope `{}`", new.scope)));
			};
			let state = ScopeState::parse(&state)?;
			if state != ScopeState::Active {
				return Err(DomainError::Precondition(format!("scope `{}` is {}: nothing new opens in it", new.scope, state.as_str())));
			}
			Some(namespace)
		};

		let requested_by = match &new.requested_by {
			Some(subject) => Some(
				user_by_subject(&mut tx, subject)
					.await?
					.ok_or_else(|| DomainError::Validation("requested_by names no account".into()))?,
			),
			None => None,
		};
		if let Some(proven) = &new.proven {
			check_proof(&mut tx, proven, requested_by).await?;
		}
		for field in &new.fields {
			if let FieldValue::User(subject) = &field.value
				&& user_by_subject(&mut tx, subject).await?.is_none()
			{
				return Err(DomainError::Validation(format!("field `{}` names no account", field.key)));
			}
		}

		let due: Option<Uuid> = sqlx::query_scalar(
			"SELECT id FROM approvals WHERE kind = $1 AND scope = $2 AND subject_ref = $3 \
			 AND ((state = 'open' AND expires_at <= $4) OR (state = 'passed' AND executable_at + $5 <= $4))",
		)
		.bind(&new.kind.name)
		.bind(&new.scope)
		.bind(&new.subject_ref)
		.bind(now)
		.bind(EXECUTION_WINDOW_SECS)
		.fetch_optional(&mut *tx)
		.await
		.map_err(repo_err)?;
		if let Some(id) = due {
			let mut stale = load(&mut tx, id, true, now).await?.ok_or_else(|| not_found(id))?;
			if stale.decision.expire_if_due(now) {
				persist(&mut tx, id, &mut stale.decision, None, &serde_json::json!({}), now).await?;
			}
		}
		let live: Option<Uuid> = sqlx::query_scalar("SELECT id FROM approvals WHERE kind = $1 AND scope = $2 AND subject_ref = $3 AND state IN ('open', 'passed')")
			.bind(&new.kind.name)
			.bind(&new.scope)
			.bind(&new.subject_ref)
			.fetch_optional(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(id) = live {
			return Err(DomainError::Conflict(format!("proposal {id} about this subject is still live")));
		}

		let admins = match &namespace {
			Some(namespace) => scope_admins(&mut tx, namespace).await?,
			None => Vec::new(),
		};
		if let (Some(Action::GrantAdmin { user, .. }), Some(namespace)) = (&new.action, &namespace) {
			let held: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM grants WHERE user_id = $1 AND target = $2 || ':admin' AND revoked_at IS NULL)")
				.bind(user)
				.bind(namespace)
				.fetch_one(&mut *tx)
				.await
				.map_err(repo_err)?;
			if held {
				return Err(DomainError::Precondition("the account already holds the scope's admin alias".into()));
			}
		}
		let policy = match &namespace {
			Some(_) => Some(current_policy(&mut tx, &new.scope).await?),
			None => None,
		};
		let fired = match &policy {
			Some(policy) if new.kind.level == ApprovalLevel::Scope => {
				let window: Vec<serde_json::Value> = sqlx::query_scalar(
					"SELECT fields FROM approvals WHERE kind = $1 AND scope = $2 AND level = 'scope' \
					 AND ((state = 'open' AND expires_at > $3) \
					      OR (state = 'passed' AND executable_at + $4 > $3) \
					      OR (state = 'executed' AND decided_at > $3 - $5))",
				)
				.bind(&new.kind.name)
				.bind(&new.scope)
				.bind(now)
				.bind(EXECUTION_WINDOW_SECS)
				.bind(ROLLING_WINDOW_SECS)
				.fetch_all(&mut *tx)
				.await
				.map_err(repo_err)?;
				let window: Vec<Vec<Field>> = window
					.into_iter()
					.map(serde_json::from_value)
					.collect::<Result<_, _>>()
					.map_err(|e| DomainError::Repository(format!("stored approval fields are unreadable: {e}")))?;
				approvals::fired_escalations(&new.kind, &new.fields, policy, &window)
			}
			_ => Vec::new(),
		};
		let resolution = approvals::resolve_level(new.kind.level, in_root, fired, admins.len());
		if resolution.level == ApprovalLevel::Platform {
			// FOR SHARE: a change of the owners stamps this row first, so it either waits for
			// this open to commit and then voids it, or commits first and is seen here.
			let changed_at: i64 = sqlx::query_scalar("SELECT changed_at FROM platform_roster FOR SHARE")
				.fetch_one(&mut *tx)
				.await
				.map_err(repo_err)?;
			let platform = current_platform_policy(&mut tx).await?;
			if let Err(reopens) = platform.admits(changed_at, now) {
				return Err(DomainError::Precondition(format!(
					"the platform owners changed recently: no platform decision opens before {reopens}"
				)));
			}
		}
		let policy_version = policy.as_ref().map_or(0, |p| p.version);
		let (roster, quorum_bps, delay_secs, ttl_secs) = match (resolution.level, &policy) {
			(ApprovalLevel::Scope, Some(policy)) => (admins, policy.quorum_bps, policy.delay_secs, policy.ttl_secs.min(MAX_TTL_SECS)),
			(ApprovalLevel::Platform, _) | (ApprovalLevel::Scope, None) => {
				if active_owners.len() < PLATFORM_MIN_ROSTER {
					return Err(DomainError::Precondition(format!(
						"fewer than {PLATFORM_MIN_ROSTER} platform owners: nobody may decide for the platform alone"
					)));
				}
				(owners, PLATFORM_QUORUM_BPS, PLATFORM_DELAY_SECS, MAX_TTL_SECS)
			}
		};
		// A service's proven initiator leaves a platform roster only (D24(1)); a scope's
		// admins decide their own scope as they always did.
		let proven_out = match (resolution.level, &new.proven) {
			(ApprovalLevel::Platform, Some(proven)) => Some(proven.user),
			(ApprovalLevel::Platform | ApprovalLevel::Scope, _) => None,
		};
		let before = roster.len();
		// Told only if taken OFF a roster they were on: a proven admin of a scope is no owner,
		// has no vote on a platform decision and no veto to cast, so a notice inviting one
		// would point at a door that is shut.
		let initiator_removed = proven_out.is_some_and(|initiator| roster.contains(&initiator));
		let roster: Vec<UserId> = roster.into_iter().filter(|u| !new.exclude.contains(u) && Some(*u) != proven_out).collect();
		// The floors count who can DECIDE: an owner on hold is on the roster with no say.
		let deciders = match resolution.level {
			ApprovalLevel::Platform => roster.iter().filter(|u| active_owners.contains(u)).count(),
			ApprovalLevel::Scope => roster.len(),
		};
		if deciders == 0 {
			return Err(DomainError::Precondition("nobody besides the one who asked and the one it would seat could decide it".into()));
		}
		// A service's proposal keeps its floor of two deciders even with the initiator gone:
		// one owner must not decide another's money alone. The code word lets the proposer
		// tell this refusal from the others: retrying without the token would put the
		// initiator back on the roster, which is the one thing this refusal exists to stop.
		if roster.len() < before && new.proposer != approvals::OWN_NAMESPACE && deciders < PLATFORM_MIN_ROSTER {
			return Err(DomainError::Precondition(format!(
				"not_enough_owners_besides_initiator: not enough active owners besides the initiator — {PLATFORM_MIN_ROSTER} others must decide it; \
				 do not retry without the token"
			)));
		}
		let threshold = approvals::threshold(roster.len(), quorum_bps);
		let mut decision = Decision::open(&roster, threshold, i64::from(delay_secs), now + i64::from(ttl_secs));
		let fields = serde_json::to_value(&new.fields).map_err(|e| DomainError::Repository(format!("approval fields do not encode: {e}")))?;
		let roster_size = i32::try_from(roster.len()).map_err(|_| DomainError::Repository("roster overflows".into()))?;
		let threshold = i32::try_from(threshold).map_err(|_| DomainError::Repository("threshold overflows".into()))?;
		let policy_version = i64::try_from(policy_version).map_err(|_| DomainError::Repository("policy version overflows".into()))?;
		sqlx::query(
			"INSERT INTO approvals (id, kind, proposer, scope, level, escalated_by, subject_ref, fields, payload_hash, requested_by, reason, roster_size, \
			 threshold, policy_version, delay_secs, created_at, expires_at, requested_by_client, dedupe_key, action, requested_by_proven) \
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)",
		)
		.bind(new.id)
		.bind(&new.kind.name)
		.bind(&new.proposer)
		.bind(&new.scope)
		.bind(level_str(resolution.level))
		.bind(&resolution.escalated_by)
		.bind(&new.subject_ref)
		.bind(fields)
		.bind(&new.payload_hash)
		.bind(requested_by)
		.bind(&new.reason)
		.bind(roster_size)
		.bind(threshold)
		.bind(policy_version)
		.bind(decision.delay_secs)
		.bind(now)
		.bind(decision.expires_at)
		.bind(&new.client)
		.bind(&new.dedupe_key)
		.bind(
			new.action
				.as_ref()
				.map(serde_json::to_value)
				.transpose()
				.map_err(|e| DomainError::Repository(format!("approval action does not encode: {e}")))?,
		)
		.bind(new.proven.is_some())
		.execute(&mut *tx)
		.await
		.map_err(|err| match err {
			// The store's own pause (migration 0038): a change of the owners committed
			// between the check above and this insert is refused like the check refuses.
			sqlx::Error::Database(db) if db.code().as_deref() == Some(PAUSE_SQLSTATE) => DomainError::Precondition(db.message().to_owned()),
			other => repo_err(other),
		})?;
		let roster_ids: Vec<Uuid> = roster.iter().map(|u| u.raw()).collect();
		sqlx::query("INSERT INTO approval_voters (approval_id, user_id) SELECT $1, unnest($2::uuid[])")
			.bind(new.id)
			.bind(&roster_ids)
			.execute(&mut *tx)
			.await
			.map_err(repo_err)?;
		if let Some(proven) = &new.proven {
			spend_proof(&mut tx, proven, new.id, now).await?;
			if initiator_removed {
				tell_initiator(&mut tx, proven.user, new.id, &new.scope, now).await?;
			}
		}
		let opener = match (new.exclude.first(), new.client.as_str()) {
			(Some(person), _) => ApprovalActor::Person(*person),
			(None, "") => ApprovalActor::Service(crate::service_caller::BRIDGE_PUBLISHER),
			(None, client) => ApprovalActor::Service(client),
		};
		let detail = serde_json::json!({
			"level": level_str(resolution.level),
			"escalated_by": resolution.escalated_by,
			"roster_size": roster_size,
			"threshold": threshold,
			"dedupe_key": new.dedupe_key,
		});
		write_events(&mut tx, new.id, &mut decision, Some(opener), &detail, now).await?;
		let stored = load(&mut tx, new.id, false, now).await?.ok_or_else(|| not_found(new.id))?;
		mail_roster(&mut tx, &stored, &new.kind).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Proposed::Opened(stored))
	}

	async fn viewer(&self, user: UserId) -> Result<ApprovalViewer, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let owner = is_owner(&mut conn, user).await?;
		let admin_of: Vec<String> = sqlx::query_scalar(
			"SELECT DISTINCT t.id FROM grants g JOIN tenants t ON t.namespace = g.namespace \
			 WHERE g.user_id = $1 AND g.revoked_at IS NULL AND g.target = g.namespace || ':admin' ORDER BY t.id",
		)
		.bind(user.raw())
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		Ok(ApprovalViewer { user, owner, admin_of })
	}

	async fn find(&self, id: Uuid) -> Result<Option<ApprovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let now = self.instant(&mut conn).await?;
		load(&mut conn, id, false, now).await
	}

	async fn list(&self, viewer: &ApprovalViewer, filter: &ApprovalFilter) -> Result<Vec<ApprovalRecord>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let now = self.instant(&mut conn).await?;
		// "Awaiting my vote" asks only what the vote would accept: a member who lost the
		// seat the roster was drawn from is refused it, so is not asked for it either.
		let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
			"SELECT {COLUMNS}{FROM} WHERE \
			 ($1 OR a.scope = ANY($2) OR a.requested_by = $3 OR EXISTS (SELECT 1 FROM approval_voters v WHERE v.approval_id = a.id AND v.user_id = $3)) \
			 AND ($4::text IS NULL OR a.scope = $4) \
			 AND ($5::text IS NULL OR (CASE WHEN a.state = 'open' AND a.expires_at <= $6 THEN 'expired' \
			                               WHEN a.state = 'passed' AND a.executable_at + $11 <= $6 THEN 'void' \
			                               ELSE a.state END) = $5) \
			 AND (NOT $7 OR (a.state = 'open' AND a.expires_at > $6 \
			      AND ((a.level = 'platform' AND $1) OR (a.level = 'scope' AND a.scope = ANY($2))) \
			      AND EXISTS (SELECT 1 FROM approval_voters v WHERE v.approval_id = a.id AND v.user_id = $3 AND v.vote = 'pending'))) \
			 AND ($8::bigint IS NULL OR (a.created_at, a.id) < ($8, $9::uuid)) \
			 ORDER BY a.created_at DESC, a.id DESC LIMIT $10"
		)))
		.bind(viewer.owner)
		.bind(&viewer.admin_of)
		.bind(viewer.user.raw())
		.bind(filter.scope.as_deref())
		.bind(filter.state.map(approvals::ApprovalState::as_str))
		.bind(now)
		.bind(filter.awaiting_my_vote)
		.bind(filter.before.map(|(at, _)| at))
		.bind(filter.before.map(|(_, id)| id))
		.bind(filter.limit)
		.bind(EXECUTION_WINDOW_SECS)
		.fetch_all(&mut *conn)
		.await
		.map_err(repo_err)?;
		records_of(&mut conn, rows, now).await
	}

	async fn vote(&self, id: Uuid, voter: UserId, vote: Vote) -> Result<ApprovalRecord, DomainError> {
		let (mut tx, mut record, now) = self.begin_locked(id).await?;
		record.decision.expire_if_due(now);
		let result = if record.decision.is_voter(voter) && record.decision.state.is_live() && !holds_seat(&mut tx, &record, voter).await? {
			Err(DomainError::Forbidden("you no longer hold the seat this roster was drawn from".into()))
		} else {
			let unseated = unseated(&mut tx, &record).await?;
			record.decision.vote(voter, vote, now, &unseated)
		};
		finish(tx, record, result, ApprovalActor::Person(voter), serde_json::json!({ "vote": vote.as_str() }), now).await
	}

	async fn veto(&self, id: Uuid, by: UserId, reason: &str) -> Result<ApprovalRecord, DomainError> {
		let (mut tx, mut record, now) = self.begin_locked(id).await?;
		record.decision.expire_if_due(now);
		let owner = is_owner(&mut tx, by).await?;
		let result = if !owner && record.decision.is_voter(by) && record.decision.state.is_live() && !holds_seat(&mut tx, &record, by).await? {
			Err(DomainError::Forbidden("you no longer hold the seat this roster was drawn from".into()))
		} else {
			record.decision.veto(by, owner, reason, now)
		};
		finish(tx, record, result, ApprovalActor::Person(by), serde_json::json!({ "reason": reason, "as_owner": owner }), now).await
	}

	async fn withdraw(&self, id: Uuid, proposer: &str, actor: ApprovalActor<'_>, reason: &str) -> Result<ApprovalRecord, DomainError> {
		let (tx, mut record, now) = self.begin_locked(id).await?;
		if record.proposer != proposer {
			return Err(not_found(id));
		}
		record.decision.expire_if_due(now);
		let result = record.decision.withdraw(now);
		finish(tx, record, result, actor, serde_json::json!({ "reason": reason }), now).await
	}

	async fn pull(&self, proposer: &str, limit: i64) -> Result<Vec<ApprovalRecord>, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let now = self.instant(&mut tx).await?;
		// `FOR SHARE`: a veto or a lapse cannot commit between choosing a row and reading it,
		// so what is served was pullable when it was read.
		let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
			"SELECT {COLUMNS}{FROM} WHERE a.proposer = $1 AND a.state = 'passed' AND a.executable_at <= $2 AND a.executable_at + $4 - $5 > $2 \
			 ORDER BY a.executable_at, a.id LIMIT $3 FOR SHARE OF a"
		)))
		.bind(proposer)
		.bind(now)
		.bind(limit)
		.bind(EXECUTION_WINDOW_SECS)
		.bind(PULL_MARGIN_SECS)
		.fetch_all(&mut *tx)
		.await
		.map_err(repo_err)?;
		let records = records_of(&mut tx, rows, now).await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(records)
	}

	async fn report(&self, id: Uuid, proposer: &str, actor: ApprovalActor<'_>, outcome: Outcome, detail: &str) -> Result<ApprovalRecord, DomainError> {
		let (tx, mut record, now) = self.begin_locked(id).await?;
		if record.proposer != proposer {
			return Err(not_found(id));
		}
		record.decision.expire_if_due(now);
		let result = record.decision.report(outcome, detail, now).map(drop);
		finish(tx, record, result, actor, serde_json::json!({ "outcome": outcome.as_str(), "detail": detail }), now).await
	}

	async fn policy(&self, scope: &str) -> Result<Option<ScopePolicy>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
			.bind(scope)
			.fetch_one(&mut *conn)
			.await
			.map_err(repo_err)?;
		if !known {
			return Ok(None);
		}
		current_policy(&mut conn, scope).await.map(Some)
	}

	async fn person(&self, who: PersonRef<'_>) -> Result<Option<(UserId, String, bool)>, DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let id = match who {
			PersonRef::Id(id) => id,
			PersonRef::Handle(handle) => match account_named(&mut conn, handle).await? {
				Named::One(id) => id,
				Named::Nobody => return Ok(None),
				Named::Several => return Err(DomainError::Validation("this handle names more than one account; name it by user_id".into())),
			},
		};
		let row: Option<(String, bool)> = sqlx::query_as("SELECT auth_subject, email_verified FROM users WHERE id = $1 AND status = 'active'")
			.bind(id.raw())
			.fetch_optional(&mut *conn)
			.await
			.map_err(repo_err)?;
		Ok(row.map(|(subject, verified)| (id, subject, verified)))
	}

	async fn platform_policy(&self) -> Result<(PlatformPolicy, i64), DomainError> {
		let mut conn = self.pool.acquire().await.map_err(repo_err)?;
		let changed_at: i64 = sqlx::query_scalar("SELECT changed_at FROM platform_roster").fetch_one(&mut *conn).await.map_err(repo_err)?;
		Ok((current_platform_policy(&mut conn).await?, changed_at))
	}

	async fn mail_outcomes(&self, limit: i64) -> Result<usize, DomainError> {
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		let now = self.instant(&mut tx).await?;
		// The effective state as `Decision::effective_state` projects it. SKIP LOCKED: a
		// proposal some act holds right now is told on the next pass, after that act.
		let due: Vec<Uuid> = sqlx::query_scalar(
			"SELECT id FROM approvals, LATERAL (SELECT CASE \
			   WHEN state = 'open' AND expires_at <= $1 THEN 'expired' \
			   WHEN state = 'passed' AND executable_at + $2 <= $1 THEN 'void' \
			   ELSE state END AS effective) e \
			 WHERE e.effective <> 'open' AND mailed_state IS DISTINCT FROM e.effective \
			 ORDER BY created_at, id LIMIT $3 FOR UPDATE OF approvals SKIP LOCKED",
		)
		.bind(now)
		.bind(EXECUTION_WINDOW_SECS)
		.bind(limit)
		.fetch_all(&mut *tx)
		.await
		.map_err(repo_err)?;
		if due.is_empty() {
			return Ok(0);
		}
		let kinds: Vec<ApprovalKind> = approvals::builtin_kinds().into_iter().chain(scope_catalogs::current_kinds(&mut *tx).await?).collect();
		for id in &due {
			let record = load(&mut tx, *id, false, now).await?.ok_or_else(|| not_found(*id))?;
			let state = record.decision.effective_state(now);
			if state != approvals::ApprovalState::Open {
				mail_outcome(&mut tx, &record, state, kinds.iter().find(|k| k.name == record.kind)).await?;
			}
			sqlx::query("UPDATE approvals SET mailed_state = $2 WHERE id = $1")
				.bind(id)
				.bind(state.as_str())
				.execute(&mut *tx)
				.await
				.map_err(repo_err)?;
		}
		tx.commit().await.map_err(repo_err)?;
		Ok(due.len())
	}

	async fn execute(&self, id: Uuid) -> Result<Option<Outcome>, DomainError> {
		// A grant locks the two accounts it names before the proposal, in the order a change
		// of the owners takes them (the `users` row, then the trigger's `approvals` rows):
		// taken the other way round, the executor and an owner's role change could each
		// hold what the other waits for.
		let accounts = {
			let mut conn = self.pool.acquire().await.map_err(repo_err)?;
			match load(&mut conn, id, false, 0).await?.and_then(|r| r.action) {
				Some(Action::GrantAdmin { user, granted_by, .. }) => vec![UserId::from_raw(user), UserId::from_raw(granted_by)],
				Some(Action::InstallPolicy { .. } | Action::InstallPlatformPolicy { .. }) | None => Vec::new(),
			}
		};
		let mut tx = self.pool.begin().await.map_err(repo_err)?;
		lock_accounts(&mut tx, &accounts).await?;
		let mut record = load(&mut tx, id, true, 0).await?.ok_or_else(|| not_found(id))?;
		let now = self.instant(&mut tx).await?;
		record.as_of = now;
		if record.proposer != approvals::OWN_NAMESPACE {
			return Ok(None);
		}
		if record.decision.expire_if_due(now) {
			persist(&mut tx, id, &mut record.decision, None, &serde_json::json!({}), now).await?;
			tx.commit().await.map_err(repo_err)?;
			return Ok(None);
		}
		if !record.decision.is_pullable(now) {
			return Ok(None);
		}
		let refused = match &record.action {
			None => Some("nothing to execute was stored with it".to_owned()),
			Some(Action::GrantAdmin { user, scope, granted_by }) => match grant_by_approval(&mut tx, UserId::from_raw(*user), scope, UserId::from_raw(*granted_by), id, now).await? {
				ApprovedGrant::Granted | ApprovedGrant::AlreadyHeld => None,
				ApprovedGrant::Inapplicable(why) => Some(why.to_owned()),
			},
			Some(Action::InstallPlatformPolicy { policy }) => match policy.check() {
				Err(why) => Some(why),
				Ok(()) => {
					install_platform_policy(&mut tx, policy, id, now).await?;
					None
				}
			},
			Some(Action::InstallPolicy { scope, policy }) => {
				let kinds = scope_catalogs::current_kinds(&mut *tx).await?;
				match policy.check(&kinds) {
					Err(why) => Some(why),
					Ok(()) => {
						install_policy(&mut tx, scope, &policy.anchored(&kinds), id, now).await?;
						None
					}
				}
			}
		};
		let (outcome, detail) = match refused {
			None => (Outcome::Executed, String::new()),
			Some(why) => (Outcome::Void, clip(&why, approvals::TEXT_FIELD_BYTES)),
		};
		record.decision.report(outcome, &detail, now)?;
		persist(
			&mut tx,
			id,
			&mut record.decision,
			Some(ApprovalActor::Service(approvals::OWN_NAMESPACE)),
			&serde_json::json!({ "outcome": outcome.as_str(), "detail": detail }),
			now,
		)
		.await?;
		tx.commit().await.map_err(repo_err)?;
		Ok(Some(outcome))
	}
}

/// `text` cut to at most `max` bytes on a character boundary: an outcome detail is bounded
/// by its column.
fn clip(text: &str, max: usize) -> String {
	let mut end = text.len().min(max);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	text[..end].to_owned()
}

/// The members of `record`'s roster who no longer hold the seat it was drawn from.
async fn unseated(conn: &mut PgConnection, record: &ApprovalRecord) -> Result<Vec<UserId>, DomainError> {
	let query = match record.level {
		ApprovalLevel::Platform =>
		// A suspended owner keeps the role and has no say while suspended.
			sqlx::query_scalar("SELECT v.user_id FROM approval_voters v JOIN users u ON u.id = v.user_id WHERE v.approval_id = $1 AND (u.role <> 'owner' OR u.status <> 'active')")
				.bind(record.id),
		ApprovalLevel::Scope => sqlx::query_scalar(
			"SELECT v.user_id FROM approval_voters v WHERE v.approval_id = $1 AND NOT EXISTS ( \
			   SELECT 1 FROM grants g JOIN tenants t ON t.namespace = g.namespace JOIN users u ON u.id = g.user_id \
			   WHERE t.id = $2 AND g.user_id = v.user_id AND g.target = t.namespace || ':admin' AND g.revoked_at IS NULL AND u.status = 'active')",
		)
		.bind(record.id)
		.bind(record.scope.clone()),
	};
	let ids: Vec<Uuid> = query.fetch_all(conn).await.map_err(repo_err)?;
	Ok(ids.into_iter().map(UserId::from_raw).collect())
}

/// The policy `scope` is measured against now: its newest installed version, else the
/// default.
async fn current_policy(conn: &mut PgConnection, scope: &str) -> Result<ScopePolicy, DomainError> {
	let row: Option<(i64, i32, i32, i32, serde_json::Value)> =
		sqlx::query_as("SELECT version, quorum_bps, delay_secs, ttl_secs, thresholds FROM scope_approval_policies WHERE scope = $1 ORDER BY version DESC LIMIT 1")
			.bind(scope)
			.fetch_optional(conn)
			.await
			.map_err(repo_err)?;
	let Some((version, quorum_bps, delay_secs, ttl_secs, thresholds)) = row else {
		return Ok(ScopePolicy::default());
	};
	let positive = |v: i32, column: &str| u32::try_from(v).map_err(|_| DomainError::Repository(format!("scope_approval_policies.{column} is negative")));
	Ok(ScopePolicy {
		version: unsigned(version, "policy version")?,
		quorum_bps: positive(quorum_bps, "quorum_bps")?,
		delay_secs: positive(delay_secs, "delay_secs")?,
		ttl_secs: positive(ttl_secs, "ttl_secs")?,
		thresholds: serde_json::from_value(thresholds).map_err(|e| DomainError::Repository(format!("stored policy thresholds are unreadable: {e}")))?,
	})
}

/// The platform's policy in force: its newest installed version, else the default.
async fn current_platform_policy(conn: &mut PgConnection) -> Result<PlatformPolicy, DomainError> {
	let row: Option<(i64, i32)> = sqlx::query_as("SELECT version, cooldown_secs FROM platform_approval_policies ORDER BY version DESC LIMIT 1")
		.fetch_optional(conn)
		.await
		.map_err(repo_err)?;
	let Some((version, cooldown_secs)) = row else {
		return Ok(PlatformPolicy::default());
	};
	Ok(PlatformPolicy {
		version: unsigned(version, "platform policy version")?,
		cooldown_secs: u32::try_from(cooldown_secs).map_err(|_| DomainError::Repository("platform_approval_policies.cooldown_secs is negative".into()))?,
	})
}

/// Install `policy` as the platform's next version, on the authority of executed approval
/// `id`.
async fn install_platform_policy(conn: &mut PgConnection, policy: &PlatformPolicy, id: Uuid, now: i64) -> Result<(), DomainError> {
	advisory_lock(conn, "platform_policy").await?;
	let next = current_platform_policy(conn).await?.version + 1;
	sqlx::query("INSERT INTO platform_approval_policies (version, cooldown_secs, approval_id, installed_at) VALUES ($1, $2, $3, $4)")
		.bind(i64::try_from(next).map_err(|_| DomainError::Repository("platform policy version overflows".into()))?)
		.bind(i32::try_from(policy.cooldown_secs).map_err(|_| DomainError::Repository("a cooldown overflows".into()))?)
		.bind(id)
		.bind(now)
		.execute(conn)
		.await
		.map_err(repo_err)?;
	Ok(())
}

/// Install `policy` as `scope`'s next version, on the authority of executed approval `id`.
async fn install_policy(conn: &mut PgConnection, scope: &str, policy: &ScopePolicy, id: Uuid, now: i64) -> Result<(), DomainError> {
	// Serialises two installs into one scope, so each gets its own version.
	advisory_lock(conn, &format!("scope_policy:{scope}")).await?;
	let next = current_policy(conn, scope).await?.version + 1;
	let thresholds = serde_json::to_value(&policy.thresholds).map_err(|e| DomainError::Repository(format!("policy thresholds do not encode: {e}")))?;
	let to_i32 = |v: u32| i32::try_from(v).map_err(|_| DomainError::Repository("a policy value overflows".into()));
	sqlx::query(
		"INSERT INTO scope_approval_policies (scope, version, quorum_bps, delay_secs, ttl_secs, thresholds, approval_id, installed_at) \
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
	)
	.bind(scope)
	.bind(i64::try_from(next).map_err(|_| DomainError::Repository("policy version overflows".into()))?)
	.bind(to_i32(policy.quorum_bps)?)
	.bind(to_i32(policy.delay_secs)?)
	.bind(to_i32(policy.ttl_secs)?)
	.bind(thresholds)
	.bind(id)
	.bind(now)
	.execute(conn)
	.await
	.map_err(repo_err)?;
	Ok(())
}
