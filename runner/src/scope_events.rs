//! `scope_events` module — `ScopeEvents.PullScopeEvents`, the per-scope stream relying
//! parties project users and scopes from (`docs/SCOPES-AND-APPROVALS.md` §4).
//!
//! A service seam like `UserEvents`: mounted OUTSIDE the user auth layer, on `BIND` and on
//! the bridge TLS listener, and authenticated by a service credential
//! ([`crate::service_caller`]). The bridge token reads every scope; a client reads its own
//! scope and every scope that names it an observer. What a caller may see comes from WHO
//! is asking, never from a request field.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use evconcierge_contracts::concierge::v1::{
	PullScopeEventsRequest, PullScopeEventsResponse, ScopeEvent, ScopeGrants, ScopeMember, scope_event::Kind, scope_events_server::ScopeEvents as ScopeEventsRpc,
};
use tonic::{Request, Response, Status};

use crate::{
	ports::{ScopeEventBody, ScopeEventRecord, ScopeEventRepository},
	service_caller::{ServiceCaller, ServiceCallers},
	support::filtered_page,
};

/// The largest page served, whatever the request's `limit`.
const MAX_LIMIT: i64 = 500;
/// How far past the cursor a filtered reader's scan runs in one call. Bounds the work of a
/// pull whose caller sees little of the stream; the cursor still moves past what it scanned.
const MAX_SCAN: i64 = 10 * MAX_LIMIT;

#[derive(Clone)]
pub struct ScopeEvents {
	callers: ServiceCallers,
	events: Arc<dyn ScopeEventRepository>,
}

impl ScopeEvents {
	pub fn new(callers: ServiceCallers, events: Arc<dyn ScopeEventRepository>) -> Self {
		Self { callers, events }
	}
}

fn wire(event: ScopeEventRecord) -> ScopeEvent {
	let (user_id, auth_subject) = event.user.map(|(id, subject)| (id.to_string(), subject)).unwrap_or_default();
	let mut out = ScopeEvent {
		event_id: event.event_id.to_string(),
		position: event.position,
		scope: event.scope,
		occurred_at: event.occurred_at,
		sequence: event.sequence,
		user_id,
		auth_subject,
		..Default::default()
	};
	match event.body {
		ScopeEventBody::ScopeChanged(scope) => {
			out.kind = Kind::ScopeChanged as i32;
			out.scope_snapshot = Some(crate::scopes::wire(scope));
		}
		ScopeEventBody::GrantsChanged(permissions) => {
			out.kind = Kind::GrantsChanged as i32;
			out.grants = Some(ScopeGrants { permissions });
		}
		ScopeEventBody::MemberJoined(m) => {
			out.kind = Kind::MemberJoined as i32;
			out.member = Some(ScopeMember {
				email: m.email,
				email_verified: m.email_verified,
				username: m.username,
				preferred_name: m.preferred_name,
				status: m.status,
				kyc_level: m.kyc_level,
				token_version: m.token_version,
				lifecycle_sequence: m.lifecycle_sequence,
			});
		}
		ScopeEventBody::Unknown(kind) => {
			tracing::error!(%kind, position = out.position, "scope stream row of a kind this binary cannot name");
			out.kind = Kind::Unspecified as i32;
		}
	}
	out
}

#[tonic::async_trait]
impl ScopeEventsRpc for ScopeEvents {
	async fn pull_scope_events(&self, request: Request<PullScopeEventsRequest>) -> Result<Response<PullScopeEventsResponse>, Status> {
		let caller = self.callers.authenticate(&request, "scope events").await?;
		let req = request.into_inner();
		let limit = (req.limit as i64).clamp(1, MAX_LIMIT);
		let unavailable = |err| {
			tracing::error!("scope stream read failed: {err}");
			Status::unavailable("internal error")
		};
		let (visible, scan) = match &caller {
			ServiceCaller::Bridge => (None, limit),
			ServiceCaller::Client(client) => (Some(self.events.observed_by(&client.client_id, &client.scope).await.map_err(unavailable)?), MAX_SCAN),
		};
		let scanned = self.events.scan(req.after_position, scan, visible.as_deref()).await.map_err(unavailable)?;
		let (events, next_position) = filtered_page(scanned.into_iter().map(|e| (e.position, e.visible, e)), req.after_position, limit as usize);
		Ok(Response::new(PullScopeEventsResponse {
			events: events.into_iter().map(wire).collect(),
			next_position,
		}))
	}
}
