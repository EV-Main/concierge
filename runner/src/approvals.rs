//! `approvals` module — `ApprovalService` (people, over a first-party session) and
//! `ApprovalExecutionService` (the proposing services, by service credential):
//! `docs/SCOPES-AND-APPROVALS.md` §5, `approvals.proto`.
//!
//! The rules live in `domain::approvals`; the adapter resolves the roster and the level
//! inside the opening transaction. What is decided HERE is who is asking: a service is its
//! namespace ([`crate::service_caller`]), and every execution RPC acts only on kinds of
//! that namespace — anything else answers exactly as an unknown id does, so a proposal's
//! existence is not a probe one namespace can run against another's. A person sees what
//! [`visible`] says, and an invisible proposal is the same `NOT_FOUND`.
//!
//! This plane is also a proposer: its own `concierge:*` kinds are opened over a session
//! (the opener, proven by it, is kept off the roster) and carried out by [`run_executor`].
//! Not served yet: the approval mail (§5.5).
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::{
	approvals::{self as rules, Amount, ApprovalState, Field, FieldValue, Outcome, REASON_BYTES, TEXT_FIELD_BYTES, Vote},
	authz::Iam,
	scope_catalog::ApprovalLevel as Level,
	scopes::ROOT,
	users::UserId,
};
use evconcierge_contracts::concierge::v1::{
	self as cc, Approval, ApprovalAmount, ApprovalFieldValue, CancelApprovalRequest, GetApprovalRequest, GetProposalRequest, GetScopeApprovalPolicyRequest, ListApprovalKindsRequest,
	ListApprovalKindsResponse, ListApprovalsRequest, ListApprovalsResponse, ProposeRequest, ProposeScopeAdminGrantRequest, ProposeScopePolicyChangeRequest, PullApprovedRequest,
	PullApprovedResponse, ReportOutcomeRequest, ScopeApprovalPolicy, VetoApprovalRequest, VoteApprovalRequest, WithdrawProposalRequest,
	approval_execution_service_server::ApprovalExecutionService, approval_field_value, approval_service_server::ApprovalService, propose_scope_admin_grant_request,
};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	authz::{caller_gate, require_permission},
	ports::{ApprovalActor, ApprovalFilter, ApprovalRecord, ApprovalRepository, ApprovalViewer, NewApproval, PersonRef, Proposed, ScopeCatalogRepository, UserDirectoryRepository},
	scope_catalog::kind_to,
	service_caller::{ServiceCaller, ServiceCallers},
	support::domain_to_status,
};

const DEFAULT_PAGE: u32 = 20;
const MAX_PAGE: u32 = 100;

fn page(limit: u32) -> i64 {
	i64::from(if limit == 0 { DEFAULT_PAGE } else { limit.min(MAX_PAGE) })
}

fn approval_id(raw: &str) -> Result<Uuid, Status> {
	Uuid::parse_str(raw).map_err(|_| Status::not_found("approval not found"))
}

fn hidden() -> Status {
	Status::not_found("approval not found")
}

fn invalid(why: String) -> Status {
	Status::invalid_argument(why)
}

/// The persisted owners see everything; a scope admin their scopes'; anyone a proposal
/// that names them, as a member of its roster or as the person it is for — the last as a
/// [`Reader::Bystander`]. `None`: invisible, the same `NOT_FOUND` as an unknown id.
pub fn visible(viewer: &ApprovalViewer, record: &ApprovalRecord) -> Option<Reader> {
	if viewer.owner || viewer.admin_of.contains(&record.scope) || record.decision.is_voter(viewer.user) {
		Some(Reader::Decider)
	} else if record.requested_by.as_ref().is_some_and(|(id, _)| *id == viewer.user) {
		Some(Reader::Bystander)
	} else {
		None
	}
}

fn level_to(level: Level) -> cc::ApprovalLevel {
	match level {
		Level::Platform => cc::ApprovalLevel::Platform,
		Level::Scope => cc::ApprovalLevel::Scope,
	}
}

fn state_to(state: ApprovalState) -> cc::ApprovalState {
	match state {
		ApprovalState::Open => cc::ApprovalState::Open,
		ApprovalState::Passed => cc::ApprovalState::Passed,
		ApprovalState::Executed => cc::ApprovalState::Executed,
		ApprovalState::ExecutionFailed => cc::ApprovalState::ExecutionFailed,
		ApprovalState::Rejected => cc::ApprovalState::Rejected,
		ApprovalState::Vetoed => cc::ApprovalState::Vetoed,
		ApprovalState::Expired => cc::ApprovalState::Expired,
		ApprovalState::Cancelled => cc::ApprovalState::Cancelled,
		ApprovalState::Void => cc::ApprovalState::Void,
	}
}

fn state_from(raw: i32) -> Result<Option<ApprovalState>, Status> {
	Ok(Some(match cc::ApprovalState::try_from(raw) {
		Ok(cc::ApprovalState::Unspecified) => return Ok(None),
		Ok(cc::ApprovalState::Open) => ApprovalState::Open,
		Ok(cc::ApprovalState::Passed) => ApprovalState::Passed,
		Ok(cc::ApprovalState::Executed) => ApprovalState::Executed,
		Ok(cc::ApprovalState::ExecutionFailed) => ApprovalState::ExecutionFailed,
		Ok(cc::ApprovalState::Rejected) => ApprovalState::Rejected,
		Ok(cc::ApprovalState::Vetoed) => ApprovalState::Vetoed,
		Ok(cc::ApprovalState::Expired) => ApprovalState::Expired,
		Ok(cc::ApprovalState::Cancelled) => ApprovalState::Cancelled,
		Ok(cc::ApprovalState::Void) => ApprovalState::Void,
		Err(_) => return Err(Status::invalid_argument("unknown approval state")),
	}))
}

fn vote_to(vote: Vote) -> cc::ApprovalVote {
	match vote {
		Vote::Pending => cc::ApprovalVote::Pending,
		Vote::For => cc::ApprovalVote::For,
		Vote::Against => cc::ApprovalVote::Against,
	}
}

fn outcome_to(outcome: Option<Outcome>) -> cc::ApprovalOutcome {
	match outcome {
		None => cc::ApprovalOutcome::Unspecified,
		Some(Outcome::Executed) => cc::ApprovalOutcome::Executed,
		Some(Outcome::Failed) => cc::ApprovalOutcome::Failed,
		Some(Outcome::Void) => cc::ApprovalOutcome::Void,
	}
}

fn field_to(field: Field) -> ApprovalFieldValue {
	use approval_field_value::Value;
	ApprovalFieldValue {
		key: field.key,
		value: Some(match field.value {
			FieldValue::Text(text) => Value::Text(text),
			FieldValue::Amount(Amount { value, currency }) => Value::Amount(ApprovalAmount { value, currency }),
			FieldValue::Bps(bps) => Value::Bps(bps),
			FieldValue::Flag(flag) => Value::Flag(flag),
			FieldValue::User(subject) => Value::AuthSubject(subject),
			FieldValue::Timestamp(at) => Value::Timestamp(at),
			FieldValue::Count(count) => Value::Count(count),
		}),
	}
}

fn field_from(field: ApprovalFieldValue) -> Result<Field, Status> {
	use approval_field_value::Value;
	let value = match field.value {
		Some(Value::Text(text)) => FieldValue::Text(text),
		Some(Value::Amount(ApprovalAmount { value, currency })) => FieldValue::Amount(Amount { value, currency }),
		Some(Value::Bps(bps)) => FieldValue::Bps(bps),
		Some(Value::Flag(flag)) => FieldValue::Flag(flag),
		Some(Value::AuthSubject(subject)) => FieldValue::User(subject),
		Some(Value::Timestamp(at)) => FieldValue::Timestamp(at),
		Some(Value::Count(count)) => FieldValue::Count(count),
		None => return Err(invalid(format!("field `{}` carries no value", field.key))),
	};
	Ok(Field { key: field.key, value })
}

/// Who reads a proposal, for what the wire form may carry about the deciders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reader {
	/// One who decides or answers for the scope: a persisted owner, an admin of its scope,
	/// a member of its roster. Sees every address.
	Decider,
	/// Anyone else who may see it — the person it names as `requested_by`: the deciders'
	/// addresses are not theirs to read.
	Bystander,
	/// The proposing service: it learns how its proposal stands, never who the deciders
	/// are — no address, no cross-plane subject, not who vetoed.
	Service,
}

/// The wire form, as `reader` may see it. The state is the one a reader sees at the
/// record's instant: an open proposal past its deadline reads as expired and a passed one
/// past its execution window as void, dated at that deadline, before anything wrote so.
pub fn approval_to(record: ApprovalRecord, reader: Reader) -> Approval {
	let decision = &record.decision;
	let now = record.as_of;
	let state = decision.effective_state(now);
	let decided_at = decision.effective_decided_at(now).unwrap_or(0);
	let (requested_by, mut requested_by_email) = record.requested_by.map(|(_, p)| (p.auth_subject, p.email)).unwrap_or_default();
	let mut vetoed_by = record.vetoed_by.map(|p| p.auth_subject).unwrap_or_default();
	let mut voters: Vec<cc::ApprovalVoter> = decision
		.voters
		.iter()
		.zip(record.voters)
		.map(|(v, p)| cc::ApprovalVoter {
			auth_subject: p.auth_subject,
			email: p.email,
			vote: vote_to(v.vote) as i32,
			voted_at: v.voted_at,
		})
		.collect();
	match reader {
		Reader::Decider => {}
		Reader::Bystander => voters.iter_mut().for_each(|v| v.email.clear()),
		Reader::Service => {
			requested_by_email.clear();
			vetoed_by.clear();
			for voter in &mut voters {
				voter.email.clear();
				voter.auth_subject.clear();
			}
		}
	}
	Approval {
		id: record.id.to_string(),
		kind: record.kind,
		scope: record.scope,
		level: level_to(record.level) as i32,
		escalated_by: record.escalated_by,
		state: state_to(state) as i32,
		subject_ref: record.subject_ref,
		fields: record.fields.into_iter().map(field_to).collect(),
		payload_hash: record.payload_hash,
		requested_by,
		requested_by_email,
		reason: record.reason,
		voters,
		threshold: decision.threshold,
		policy_version: record.policy_version,
		created_at: record.created_at,
		expires_at: decision.expires_at,
		passed_at: decision.passed_at.unwrap_or(0),
		executable_at: decision.executable_at.unwrap_or(0),
		decided_at,
		vetoed_by,
		veto_reason: decision.veto_reason.clone(),
		void_reason: decision.void_reason.clone(),
		outcome: outcome_to(decision.outcome) as i32,
		outcome_detail: decision.outcome_detail.clone(),
		proposer: record.proposer,
		version: decision.version,
		requested_by_client: record.requested_by_client,
		execute_by: decision.execute_by().unwrap_or(0),
	}
}

fn policy_to(scope: &str, policy: rules::ScopePolicy) -> ScopeApprovalPolicy {
	ScopeApprovalPolicy {
		scope: scope.to_owned(),
		version: policy.version,
		quorum_bps: policy.quorum_bps,
		delay_secs: policy.delay_secs,
		ttl_secs: policy.ttl_secs,
		thresholds: policy
			.thresholds
			.into_iter()
			.map(|t| cc::ApprovalThreshold {
				kind: t.kind,
				parameter: t.parameter,
				value: t.value,
			})
			.collect(),
	}
}

/// A list cursor: the `(created_at, id)` of a page's last row. Opaque to the caller.
fn cursor_to(record: &ApprovalRecord) -> String {
	format!("{}_{}", record.created_at, record.id)
}

fn cursor_from(raw: &str) -> Result<Option<(i64, Uuid)>, Status> {
	if raw.is_empty() {
		return Ok(None);
	}
	raw.split_once('_')
		.and_then(|(at, id)| Some((at.parse().ok()?, Uuid::parse_str(id).ok()?)))
		.map(Some)
		.ok_or_else(|| Status::invalid_argument("cursor is not one this service handed out"))
}

/// `ApprovalService`: the human side, inside the user auth layer.
#[derive(Clone)]
pub struct Approvals {
	users: Arc<dyn UserDirectoryRepository>,
	break_glass: Arc<crate::authz::BreakGlass>,
	approvals: Arc<dyn ApprovalRepository>,
	catalogs: Arc<dyn ScopeCatalogRepository>,
}

impl Approvals {
	pub fn new(
		users: Arc<dyn UserDirectoryRepository>,
		break_glass: Arc<crate::authz::BreakGlass>,
		approvals: Arc<dyn ApprovalRepository>,
		catalogs: Arc<dyn ScopeCatalogRepository>,
	) -> Self {
		Self {
			users,
			break_glass,
			approvals,
			catalogs,
		}
	}

	/// The signed-in person, gated as every user RPC is (status, `token_version`). A
	/// token naming no account here has nothing to see.
	async fn caller<T>(&self, request: &Request<T>) -> Result<UserId, Status> {
		let gate = caller_gate(self.users.as_ref(), request).await?;
		match (gate.id, gate.record) {
			(Some(id), Some(_)) => Ok(id),
			_ => Err(Status::permission_denied("no account behind this token")),
		}
	}

	async fn viewer<T>(&self, request: &Request<T>) -> Result<ApprovalViewer, Status> {
		let user = self.caller(request).await?;
		self.approvals.viewer(user).await.map_err(domain_to_status)
	}

	async fn visible_record(&self, viewer: &ApprovalViewer, id: Uuid) -> Result<(ApprovalRecord, Reader), Status> {
		let record = self.approvals.find(id).await.map_err(domain_to_status)?.ok_or_else(hidden)?;
		let reader = visible(viewer, &record).ok_or_else(hidden)?;
		Ok((record, reader))
	}
}

#[tonic::async_trait]
impl ApprovalService for Approvals {
	async fn list_approval_kinds(&self, request: Request<ListApprovalKindsRequest>) -> Result<Response<ListApprovalKindsResponse>, Status> {
		self.caller(&request).await?;
		let catalogs = self.catalogs.all_current().await.map_err(domain_to_status)?;
		let kinds = rules::builtin_kinds()
			.into_iter()
			.map(|k| kind_to(k, rules::OWN_NAMESPACE))
			.chain(
				catalogs
					.into_iter()
					.flat_map(|(namespace, catalog)| catalog.approval_kinds.into_iter().map(move |k| kind_to(k, &namespace))),
			)
			.collect();
		Ok(Response::new(ListApprovalKindsResponse { kinds }))
	}

	async fn get_scope_approval_policy(&self, request: Request<GetScopeApprovalPolicyRequest>) -> Result<Response<ScopeApprovalPolicy>, Status> {
		let viewer = self.viewer(&request).await?;
		let scope = request.into_inner().scope;
		if scope == ROOT {
			return Err(Status::invalid_argument("scope `main` has no policy: it is decided by the platform owners' consilium"));
		}
		if !viewer.owner && !viewer.admin_of.contains(&scope) {
			return Err(Status::permission_denied("a scope's policy is read by its admins and the platform owners"));
		}
		let policy = self
			.approvals
			.policy(&scope)
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found(format!("unknown scope `{scope}`")))?;
		Ok(Response::new(policy_to(&scope, policy)))
	}

	async fn list_approvals(&self, request: Request<ListApprovalsRequest>) -> Result<Response<ListApprovalsResponse>, Status> {
		let viewer = self.viewer(&request).await?;
		let req = request.into_inner();
		let limit = page(req.limit);
		let filter = ApprovalFilter {
			scope: (!req.scope.is_empty()).then_some(req.scope),
			state: state_from(req.state)?,
			awaiting_my_vote: req.awaiting_my_vote,
			limit,
			before: cursor_from(&req.cursor)?,
		};
		let records = self.approvals.list(&viewer, &filter).await.map_err(domain_to_status)?;
		let next_cursor = match records.last() {
			Some(last) if i64::try_from(records.len()).is_ok_and(|n| n == limit) => cursor_to(last),
			_ => String::new(),
		};
		Ok(Response::new(ListApprovalsResponse {
			approvals: records
				.into_iter()
				.map(|r| {
					// The store filtered by the same rule; a row it let through is at least the
					// asker's own proposal.
					let reader = visible(&viewer, &r).unwrap_or(Reader::Bystander);
					approval_to(r, reader)
				})
				.collect(),
			next_cursor,
		}))
	}

	async fn get_approval(&self, request: Request<GetApprovalRequest>) -> Result<Response<Approval>, Status> {
		let viewer = self.viewer(&request).await?;
		let id = approval_id(&request.into_inner().approval_id)?;
		let (record, reader) = self.visible_record(&viewer, id).await?;
		Ok(Response::new(approval_to(record, reader)))
	}

	async fn vote_approval(&self, request: Request<VoteApprovalRequest>) -> Result<Response<Approval>, Status> {
		let viewer = self.viewer(&request).await?;
		let req = request.into_inner();
		let id = approval_id(&req.approval_id)?;
		let vote = match cc::ApprovalVote::try_from(req.vote) {
			Ok(cc::ApprovalVote::For) => Vote::For,
			Ok(cc::ApprovalVote::Against) => Vote::Against,
			Ok(cc::ApprovalVote::Pending | cc::ApprovalVote::Unspecified) | Err(_) => return Err(Status::invalid_argument("a vote is FOR or AGAINST")),
		};
		let (_, reader) = self.visible_record(&viewer, id).await?;
		let record = self.approvals.vote(id, viewer.user, vote).await.map_err(domain_to_status)?;
		Ok(Response::new(approval_to(record, reader)))
	}

	async fn veto_approval(&self, request: Request<VetoApprovalRequest>) -> Result<Response<Approval>, Status> {
		let viewer = self.viewer(&request).await?;
		let req = request.into_inner();
		let id = approval_id(&req.approval_id)?;
		rules::check_text("a veto reason", &req.reason, REASON_BYTES).map_err(invalid)?;
		let (_, reader) = self.visible_record(&viewer, id).await?;
		let record = self.approvals.veto(id, viewer.user, &req.reason).await.map_err(domain_to_status)?;
		tracing::warn!(approval = %id, by = %viewer.user, "approval vetoed");
		Ok(Response::new(approval_to(record, reader)))
	}

	async fn cancel_approval(&self, request: Request<CancelApprovalRequest>) -> Result<Response<Approval>, Status> {
		let viewer = self.viewer(&request).await?;
		let id = approval_id(&request.into_inner().approval_id)?;
		let (record, reader) = self.visible_record(&viewer, id).await?;
		// Only a `concierge:*` proposal has an opener a session proved; a service's is
		// withdrawn by its proposer or vetoed.
		let opened_it = record.proposer == rules::OWN_NAMESPACE && record.requested_by.as_ref().is_some_and(|(by, _)| *by == viewer.user);
		if !opened_it {
			return Err(Status::permission_denied("only the person who opened this plane's own proposal cancels it"));
		}
		let record = self
			.approvals
			.withdraw(id, rules::OWN_NAMESPACE, ApprovalActor::Person(viewer.user), "")
			.await
			.map_err(domain_to_status)?;
		Ok(Response::new(approval_to(record, reader)))
	}

	async fn propose_scope_admin_grant(&self, request: Request<ProposeScopeAdminGrantRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		require_permission(self.users.as_ref(), &self.break_glass, &request, Iam::Grant).await?;
		let req = request.into_inner();
		if req.scope == ROOT {
			return Err(Status::invalid_argument("scope `main` has no admins: its deciders are the platform owners"));
		}
		rules::check_text("reason", &req.reason, REASON_BYTES).map_err(invalid)?;
		let named = match &req.subject {
			Some(propose_scope_admin_grant_request::Subject::UserId(raw)) =>
				PersonRef::Id(UserId::from_raw(Uuid::parse_str(raw).map_err(|_| Status::invalid_argument("user_id is not a user id"))?)),
			Some(propose_scope_admin_grant_request::Subject::Account(handle)) => PersonRef::Handle(handle),
			None => return Err(Status::invalid_argument("name the account by user_id or account")),
		};
		let (subject, subject_ref_name) = self
			.approvals
			.person(named)
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::not_found("no active account by that name"))?;
		// The grant names its opener as `granted_by`, and nobody grants to themselves
		// (`grants_not_to_self`).
		if subject == caller {
			return Err(Status::permission_denied("nobody proposes themselves as a scope's admin"));
		}
		let fields = vec![Field {
			key: "account".into(),
			value: FieldValue::User(subject_ref_name),
		}];
		let action = rules::Action::GrantAdmin {
			user: subject.raw(),
			scope: req.scope.clone(),
			granted_by: caller.raw(),
		};
		let record = self
			.open_own(caller, rules::SCOPE_ADMIN_GRANT, req.scope, format!("user:{}", subject.raw()), fields, req.reason, action)
			.await?;
		Ok(Response::new(record))
	}

	async fn propose_scope_policy_change(&self, request: Request<ProposeScopePolicyChangeRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		let viewer = self.approvals.viewer(caller).await.map_err(domain_to_status)?;
		let req = request.get_ref();
		let wanted = req.policy.clone().ok_or_else(|| Status::invalid_argument("name the policy to install"))?;
		if wanted.scope == ROOT {
			return Err(Status::invalid_argument("scope `main` has no policy: it is decided by the platform owners' consilium"));
		}
		if !viewer.admin_of.contains(&wanted.scope) {
			require_permission(self.users.as_ref(), &self.break_glass, &request, Iam::Grant)
				.await
				.map_err(|_| Status::permission_denied("a scope's policy change is opened by its admins or a granting seat"))?;
		}
		let reason = request.into_inner().reason;
		rules::check_text("reason", &reason, REASON_BYTES).map_err(invalid)?;
		let policy = rules::ScopePolicy {
			version: 0,
			quorum_bps: wanted.quorum_bps,
			delay_secs: wanted.delay_secs,
			ttl_secs: wanted.ttl_secs,
			thresholds: wanted
				.thresholds
				.into_iter()
				.map(|t| rules::Threshold {
					kind: t.kind,
					parameter: t.parameter,
					value: t.value,
				})
				.collect(),
		};
		let kinds: Vec<_> = self
			.catalogs
			.all_current()
			.await
			.map_err(domain_to_status)?
			.into_iter()
			.flat_map(|(_, catalog)| catalog.approval_kinds)
			.collect();
		policy.check(&kinds).map_err(invalid)?;
		// One live change per scope: the subject is the scope's policy, named by a UUID
		// derived from the scope so every change of it collides on the live-subject index.
		let digest = Sha256::digest(format!("scope_policy:{}", wanted.scope).as_bytes());
		let mut bytes = [0u8; 16];
		bytes.copy_from_slice(&digest[..16]);
		let subject_ref = format!("scope_policy:{}", Uuid::from_bytes(bytes));
		let fields = rules::policy_fields(&policy);
		let action = rules::Action::InstallPolicy {
			scope: wanted.scope.clone(),
			policy,
		};
		let record = self.open_own(caller, rules::SCOPE_POLICY_CHANGE, wanted.scope, subject_ref, fields, reason, action).await?;
		Ok(Response::new(record))
	}
}

impl Approvals {
	/// Open one of this plane's own kinds for `opener`, who is proven by the session and
	/// so kept off the roster (D23).
	#[allow(clippy::too_many_arguments)] // why: every argument is a distinct part of the proposal; a struct for one private call would only rename them
	async fn open_own(&self, opener: UserId, kind: &str, scope: String, subject_ref: String, fields: Vec<Field>, reason: String, action: rules::Action) -> Result<Approval, Status> {
		let kind = rules::builtin_kinds()
			.into_iter()
			.find(|k| k.name == kind)
			.ok_or_else(|| Status::internal("a built-in kind is missing"))?;
		let fields = rules::check_fields(&kind, fields).map_err(invalid)?;
		let (_, opener_subject) = self
			.approvals
			.person(PersonRef::Id(opener))
			.await
			.map_err(domain_to_status)?
			.ok_or_else(|| Status::permission_denied("no active account behind this token"))?;
		let payload_hash = hex(&Sha256::digest(rules::payload_preimage(&kind.name, &scope, &subject_ref, &fields)));
		let new = NewApproval {
			id: Uuid::new_v4(),
			kind,
			proposer: rules::OWN_NAMESPACE.to_owned(),
			scope,
			subject_ref,
			fields,
			payload_hash,
			requested_by: Some(opener_subject),
			reason,
			dedupe_key: Uuid::new_v4().to_string(),
			client: String::new(),
			exclude: Some(opener),
			action: Some(action),
		};
		let record = match self.approvals.propose(new).await.map_err(domain_to_status)? {
			Proposed::Opened(record) | Proposed::Existing(record) => record,
			Proposed::Saturated => return Err(Status::resource_exhausted("too many of this plane's own proposals are live in this scope")),
		};
		tracing::info!(approval = %record.id, kind = %record.kind, scope = %record.scope, by = %opener, "approval opened over a session");
		let viewer = self.approvals.viewer(opener).await.map_err(domain_to_status)?;
		let reader = visible(&viewer, &record).unwrap_or(Reader::Bystander);
		Ok(approval_to(record, reader))
	}
}

/// `ApprovalExecutionService`: the proposing services, outside the user auth layer.
#[derive(Clone)]
pub struct ApprovalExecution {
	callers: ServiceCallers,
	approvals: Arc<dyn ApprovalRepository>,
	catalogs: Arc<dyn ScopeCatalogRepository>,
}

impl ApprovalExecution {
	pub fn new(callers: ServiceCallers, approvals: Arc<dyn ApprovalRepository>, catalogs: Arc<dyn ScopeCatalogRepository>) -> Self {
		Self { callers, approvals, catalogs }
	}

	async fn caller<T>(&self, request: &Request<T>) -> Result<ServiceCaller, Status> {
		self.callers.authenticate(request, "approval execution").await
	}

	/// The proposal, if it is `namespace`'s; any other is the same `NOT_FOUND` as an
	/// unknown id.
	async fn own(&self, namespace: &str, id: Uuid) -> Result<ApprovalRecord, Status> {
		match self.approvals.find(id).await.map_err(domain_to_status)? {
			Some(record) if record.proposer == namespace => Ok(record),
			_ => Err(hidden()),
		}
	}
}

/// Who the history names for a service's act: the client, or `bridge` for the money plane.
fn service_actor(caller: &ServiceCaller) -> ApprovalActor<'_> {
	ApprovalActor::Service(caller.publisher())
}

#[tonic::async_trait]
impl ApprovalExecutionService for ApprovalExecution {
	async fn propose(&self, request: Request<ProposeRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		if let ServiceCaller::Client(client) = &caller
			&& client.scope_closed
		{
			return Err(Status::failed_precondition("the scope is closed: nothing new is accepted from it"));
		}
		let namespace = caller.namespace().to_owned();
		let req = request.into_inner();
		if req.kind.split_once(':').map(|(ns, _)| ns) != Some(namespace.as_str()) {
			return Err(Status::permission_denied(format!("a proposal is opened only by its kind's namespace; yours is `{namespace}`")));
		}
		// A relying party speaks for its own scope only; the money plane, which holds every
		// scope's accounts, for any (decided).
		if let ServiceCaller::Client(client) = &caller
			&& client.scope != req.scope
		{
			return Err(Status::permission_denied(format!("a client opens proposals in its own scope `{}` only", client.scope)));
		}
		let kind = self
			.catalogs
			.current(&namespace)
			.await
			.map_err(domain_to_status)?
			.and_then(|catalog| catalog.approval_kinds.into_iter().find(|k| k.name == req.kind))
			.ok_or_else(|| Status::invalid_argument(format!("unknown approval kind `{}`", req.kind)))?;
		rules::check_subject_ref(&req.subject_ref).map_err(invalid)?;
		rules::check_text("reason", &req.reason, REASON_BYTES).map_err(invalid)?;
		rules::check_dedupe_key(&req.dedupe_key).map_err(invalid)?;
		if !req.requested_by.is_empty() {
			rules::check_auth_subject("requested_by", &req.requested_by).map_err(invalid)?;
		}
		let fields = req.fields.into_iter().map(field_from).collect::<Result<Vec<_>, _>>()?;
		let fields = rules::check_fields(&kind, fields).map_err(invalid)?;
		let payload_hash = hex(&Sha256::digest(rules::payload_preimage(&kind.name, &req.scope, &req.subject_ref, &fields)));
		let client = match &caller {
			ServiceCaller::Bridge => String::new(),
			ServiceCaller::Client(client) => client.client_id.clone(),
		};
		let new = NewApproval {
			id: Uuid::new_v4(),
			kind,
			proposer: namespace,
			scope: req.scope,
			subject_ref: req.subject_ref,
			fields,
			payload_hash,
			requested_by: (!req.requested_by.is_empty()).then_some(req.requested_by),
			reason: req.reason,
			dedupe_key: req.dedupe_key,
			client,
			exclude: None,
			action: None,
		};
		let record = match self.approvals.propose(new).await.map_err(domain_to_status)? {
			Proposed::Opened(record) => {
				tracing::info!(approval = %record.id, kind = %record.kind, scope = %record.scope, level = ?record.level, escalated_by = ?record.escalated_by, "approval proposed");
				record
			}
			Proposed::Existing(record) => record,
			Proposed::Saturated => {
				return Err(Status::resource_exhausted(format!(
					"`{}` already holds {} live proposals; withdraw or wait for some before opening more",
					caller.namespace(),
					rules::MAX_LIVE_PER_PROPOSER
				)));
			}
		};
		Ok(Response::new(approval_to(record, Reader::Service)))
	}

	async fn withdraw_proposal(&self, request: Request<WithdrawProposalRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		let req = request.into_inner();
		let id = approval_id(&req.approval_id)?;
		if !req.reason.is_empty() {
			rules::check_text("reason", &req.reason, REASON_BYTES).map_err(invalid)?;
		}
		let record = self
			.approvals
			.withdraw(id, caller.namespace(), service_actor(&caller), &req.reason)
			.await
			.map_err(|err| match err {
				domain::error::DomainError::NotFound { .. } => hidden(),
				other => domain_to_status(other),
			})?;
		Ok(Response::new(approval_to(record, Reader::Service)))
	}

	async fn get_proposal(&self, request: Request<GetProposalRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		let id = approval_id(&request.into_inner().approval_id)?;
		let record = self.own(caller.namespace(), id).await?;
		Ok(Response::new(approval_to(record, Reader::Service)))
	}

	async fn pull_approved(&self, request: Request<PullApprovedRequest>) -> Result<Response<PullApprovedResponse>, Status> {
		let caller = self.caller(&request).await?;
		let limit = page(request.into_inner().limit);
		let records = self.approvals.pull(caller.namespace(), limit).await.map_err(domain_to_status)?;
		Ok(Response::new(PullApprovedResponse {
			approvals: records.into_iter().map(|r| approval_to(r, Reader::Service)).collect(),
		}))
	}

	async fn report_outcome(&self, request: Request<ReportOutcomeRequest>) -> Result<Response<Approval>, Status> {
		let caller = self.caller(&request).await?;
		let req = request.into_inner();
		let id = approval_id(&req.approval_id)?;
		let outcome = match cc::ApprovalOutcome::try_from(req.outcome) {
			Ok(cc::ApprovalOutcome::Executed) => Outcome::Executed,
			Ok(cc::ApprovalOutcome::Failed) => Outcome::Failed,
			Ok(cc::ApprovalOutcome::Void) => Outcome::Void,
			Ok(cc::ApprovalOutcome::Unspecified) | Err(_) => return Err(Status::invalid_argument("an outcome is EXECUTED, FAILED or VOID")),
		};
		let detail_required = match outcome {
			Outcome::Executed => false,
			Outcome::Failed | Outcome::Void => true,
		};
		if detail_required || !req.detail.is_empty() {
			rules::check_text("detail", &req.detail, TEXT_FIELD_BYTES).map_err(invalid)?;
		}
		let record = self
			.approvals
			.report(id, caller.namespace(), service_actor(&caller), outcome, &req.detail)
			.await
			.map_err(|err| match err {
				domain::error::DomainError::NotFound { .. } => hidden(),
				other => domain_to_status(other),
			})?;
		tracing::info!(approval = %id, outcome = outcome.as_str(), by = caller.publisher(), "approval outcome reported");
		Ok(Response::new(approval_to(record, Reader::Service)))
	}
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// How many due `concierge:*` decisions one executor pass takes on.
const EXECUTOR_BATCH: i64 = 100;

/// One pass of this plane's executor: carry out every passed `concierge:*` proposal that
/// is due, each in its own transaction with its outcome. Returns how many it closed.
pub async fn execute_due(approvals: &dyn ApprovalRepository) -> Result<usize, domain::error::DomainError> {
	let mut closed = 0;
	for due in approvals.pull(rules::OWN_NAMESPACE, EXECUTOR_BATCH).await? {
		if let Some(outcome) = approvals.execute(due.id).await? {
			tracing::info!(approval = %due.id, kind = %due.kind, scope = %due.scope, outcome = outcome.as_str(), "approval executed by this plane");
			closed += 1;
		}
	}
	Ok(closed)
}

/// The executor loop (D23): what this plane's own approvals do once passed. A second loop
/// beside the hold sweep, because a passed decision nobody carries out lapses unexecuted
/// after its window — and unlike a service, this plane has nobody else to pull it.
pub async fn run_executor(approvals: Arc<dyn ApprovalRepository>, interval: std::time::Duration) {
	tracing::info!(interval_secs = interval.as_secs(), "approval executor started");
	loop {
		match execute_due(approvals.as_ref()).await {
			Ok(closed) if usize::try_from(EXECUTOR_BATCH).is_ok_and(|batch| closed >= batch) => continue,
			Ok(_) => {}
			Err(err) => tracing::error!(%err, "the approval executor failed; passed concierge:* decisions are not being carried out"),
		}
		tokio::time::sleep(interval).await;
	}
}
