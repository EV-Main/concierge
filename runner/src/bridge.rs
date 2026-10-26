//! `bridge` module — the cross-plane (identity → money) producer seam.
//!
//! The ONLY coupling between the two planes is this ONE-WAY bridge: concierge emits
//! [`UserLifecycleEvent`]s to `user_outbox`, and the banking money plane PULLS them
//! over [`UserEvents::pull_user_lifecycle`] to gate/freeze money ops. Concierge never
//! calls banking.
//!
//! This is a service-to-service seam, NOT a user surface — it is authenticated by a
//! shared bridge service token (config `BRIDGE_SERVICE_TOKEN`), checked here rather
//! than via the user `grpc_auth_layer` (which verifies user access tokens against the
//! JWKS). The pull is READ-ONLY: rows are never deleted, because banking dedupes by
//! `event_id` and orders per-user by `sequence` — concierge keeps the durable log.
//!
//! WHY a shared token and not mTLS: this is the platform-bring-up transport. Graduate
//! to mTLS/SPIFFE workload identity at platform scale.
//!
//! A RELYING PARTY reads the same RPC with its client credential
//! ([`crate::service_caller`]): only the users visible to the scopes it reads
//! (`scope_members`), only rows past the snapshot its MEMBER_JOINED carried, and each row
//! without the money plane's seat set. The bridge token's page is unchanged.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use evconcierge_contracts::concierge::v1::{
	PullUserLifecycleRequest, PullUserLifecycleResponse, SeatPermissions, UserLifecycleEvent, user_events_server::UserEvents, user_lifecycle_event::Kind,
};
use sqlx::PgPool;
use tonic::{Request, Response, Status};

use crate::{
	infrastructure::{relying_parties::PgRelyingParties, scope_events::PgScopeEvents},
	ports::ScopeEventRepository,
	service_caller::{ClientCaller, ServiceCaller, ServiceCallers},
	support::filtered_page,
};

/// The largest page the bridge will serve, regardless of the request's `limit`. Caps a
/// single pull so one call can't scan the whole outbox.
const MAX_LIMIT: i64 = 500;
/// How far past the cursor a relying party's filtered scan runs in one call.
const MAX_SCAN: i64 = 10 * MAX_LIMIT;

const OUTBOX_COLUMNS: &str =
	"o.position, o.user_id, o.kind, o.kyc_level, o.occurred_at, o.sequence, o.event_id, o.auth_subject, o.email, o.email_verified, o.token_version, o.role, o.permissions";

/// The cross-plane bridge producer. Serves `user_outbox` rows to the banking puller and,
/// filtered and redacted, to relying parties (`docs/SCOPES-AND-APPROVALS.md` §4.2).
/// Cheaply cloneable (pool + token behind `Arc`s).
#[derive(Clone)]
pub struct Bridge {
	pool: PgPool,
	/// The bridge token (`None` ⇒ the money plane is refused, fail-closed: never leak the
	/// outbox) or a relying party's client credential.
	callers: ServiceCallers,
	scopes: Arc<dyn ScopeEventRepository>,
}

impl Bridge {
	pub fn new(pool: PgPool, token: Option<String>) -> Self {
		Self {
			callers: ServiceCallers::new(token, Arc::new(PgRelyingParties::new(pool.clone()))),
			scopes: Arc::new(PgScopeEvents::new(pool.clone())),
			pool,
		}
	}

	/// The money plane's page, exactly as it always was: every row, the cursor at the last
	/// row served.
	async fn unfiltered(&self, after: i64, limit: i64) -> Result<PullUserLifecycleResponse, sqlx::Error> {
		let rows = sqlx::query_as::<_, OutboxRow>(sqlx::AssertSqlSafe(format!(
			"SELECT {OUTBOX_COLUMNS}, TRUE AS visible FROM user_outbox o WHERE o.position > $1 ORDER BY o.position ASC LIMIT $2"
		)))
		.bind(after)
		.bind(limit)
		.fetch_all(&self.pool)
		.await?;
		let next_position = rows.last().map(|r| r.position).unwrap_or(after);
		let events = rows.into_iter().map(OutboxRow::into_event).collect();
		Ok(PullUserLifecycleResponse { events, next_position })
	}

	/// A relying party's page: the users visible to the scopes it reads, from the first
	/// row their MEMBER_JOINED snapshot does not already reflect, with the money plane's
	/// seat set taken out.
	async fn filtered(&self, client: &ClientCaller, after: i64, limit: i64) -> Result<PullUserLifecycleResponse, Status> {
		let scopes = self.scopes.observed_by(&client.client_id, &client.scope).await.map_err(|err| {
			tracing::error!("relying party scopes unreadable: {err}");
			Status::unavailable("internal error")
		})?;
		let rows = sqlx::query_as::<_, OutboxRow>(sqlx::AssertSqlSafe(format!(
			"SELECT {OUTBOX_COLUMNS}, EXISTS ( \
				SELECT 1 FROM scope_members m WHERE m.user_id = o.user_id AND m.scope = ANY($3) AND o.sequence > m.lifecycle_sequence \
			 ) AS visible \
			 FROM user_outbox o WHERE o.position > $1 ORDER BY o.position ASC LIMIT $2"
		)))
		.bind(after)
		.bind(MAX_SCAN)
		.bind(&scopes)
		.fetch_all(&self.pool)
		.await
		.map_err(outbox_unavailable)?;
		let (rows, next_position) = filtered_page(rows.into_iter().map(|r| (r.position, r.visible, r)), after, limit as usize);
		let events = rows
			.into_iter()
			.map(|row| UserLifecycleEvent {
				seat_permissions: None,
				..row.into_event()
			})
			.collect();
		Ok(PullUserLifecycleResponse { events, next_position })
	}
}

// Log the real cause; never put sqlx internals on the wire.
fn outbox_unavailable(err: sqlx::Error) -> Status {
	tracing::error!("outbox read failed: {err}");
	Status::unavailable("internal error")
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
	position: i64,
	user_id: uuid::Uuid,
	kind: String,
	kyc_level: i32,
	occurred_at: i64,
	sequence: i64,
	event_id: uuid::Uuid,
	auth_subject: String,
	email: Option<String>,
	email_verified: bool,
	token_version: i64,
	role: Option<String>,
	permissions: Option<Vec<String>>,
	visible: bool,
}

impl OutboxRow {
	fn into_event(self) -> UserLifecycleEvent {
		UserLifecycleEvent {
			user_id: self.user_id.to_string(),
			kind: kind_to_proto(&self.kind) as i32,
			kyc_level: self.kyc_level as u32,
			occurred_at: self.occurred_at,
			event_id: self.event_id.to_string(),
			sequence: self.sequence as u64,
			auth_subject: self.auth_subject,
			email: self.email.unwrap_or_default(),
			email_verified: self.email_verified,
			token_version: self.token_version as u64,
			// Absent (pre-role rows) → empty; the banking puller reads empty as 'investor'.
			role: self.role.unwrap_or_default(),
			seat_permissions: self.permissions.map(|bank| SeatPermissions { bank }),
		}
	}
}

#[tonic::async_trait]
impl UserEvents for Bridge {
	async fn pull_user_lifecycle(&self, request: Request<PullUserLifecycleRequest>) -> Result<Response<PullUserLifecycleResponse>, Status> {
		let caller = self.callers.authenticate(&request, "bridge").await?;
		let req = request.into_inner();
		let limit = (req.limit as i64).clamp(1, MAX_LIMIT);
		let page = match &caller {
			ServiceCaller::Bridge => self.unfiltered(req.after_position, limit).await.map_err(outbox_unavailable)?,
			ServiceCaller::Client(client) => self.filtered(client, req.after_position, limit).await?,
		};
		Ok(Response::new(page))
	}
}

/// Map the outbox `kind` string (`UserEvent::kind()`, lockstep with the proto enum) to
/// the proto [`Kind`]. An unrecognized kind degrades to `Unspecified` rather than
/// failing the whole page.
fn kind_to_proto(kind: &str) -> Kind {
	match kind {
		"CREATED" => Kind::Created,
		"SUSPENDED" => Kind::Suspended,
		"REINSTATED" => Kind::Reinstated,
		"KYC_CHANGED" => Kind::KycChanged,
		"PERMISSIONS_CHANGED" => Kind::PermissionsChanged,
		"SESSIONS_REVOKED" => Kind::SessionsRevoked,
		"ROLE_CHANGED" => Kind::RoleChanged,
		_ => Kind::Unspecified,
	}
}

#[cfg(test)]
mod tests {
	use domain::users::UserEvent;

	use super::{Kind, kind_to_proto};

	#[test]
	fn every_user_event_kind_maps_to_a_concrete_proto_kind() {
		// Guards the bridge producer: a `UserEvent` whose `kind()` string isn't mapped
		// here degrades to `Unspecified` and is a silent no-op on the money plane — the
		// exact bug that let ROLE_CHANGED never reach banking. Keep this list exhaustive.
		for event in [
			UserEvent::Created,
			UserEvent::SessionsRevoked,
			UserEvent::Suspended,
			UserEvent::Reinstated,
			UserEvent::KycChanged,
			UserEvent::RoleChanged,
			UserEvent::PermissionsChanged,
		] {
			assert_ne!(kind_to_proto(event.kind()), Kind::Unspecified, "unmapped bridge kind: {}", event.kind());
		}
		assert_eq!(kind_to_proto("ROLE_CHANGED"), Kind::RoleChanged);
	}
}
