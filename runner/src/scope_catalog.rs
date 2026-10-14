//! `scope_catalog` module — `ScopeCatalogService`: a namespace's services publish the
//! approval kinds they alone propose and execute, and the notification topics they emit on
//! (`docs/SCOPES-AND-APPROVALS.md` §5.1, §6).
//!
//! Stored only. No approval is opened or executed from here yet; the topics are offered to
//! subscribers beside the built-in ones (`notification::topic_known`). Authenticated by a
//! service credential ([`crate::service_caller`]) and mounted outside the user auth layer:
//! the bridge token publishes `bank`, a client its own tenant's namespace — the namespace
//! is never taken from the request.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use domain::scope_catalog::{ApprovalKind, ApprovalLevel, Escalation, EscalationTest, FieldSpec, FieldType, NotificationTopic, ScopeCatalog};
use evconcierge_contracts::concierge::v1::{
	self as cc, ApprovalEscalation, ApprovalFieldSpec, ApprovalKindSpec, GetScopeCatalogRequest, NotificationTopicSpec, PublishScopeCatalogRequest, PublishScopeCatalogResponse,
	scope_catalog_service_server::ScopeCatalogService,
};
use tonic::{Request, Response, Status};

use crate::{
	notification::TOPICS,
	ports::{PublishOutcome, ScopeCatalogRepository},
	service_caller::{ServiceCaller, ServiceCallers},
};

/// How far ahead of this plane's clock a version may lie — `PublishCatalog`'s rule, for
/// the same reason: a version nothing can supersede would freeze the namespace's catalog.
const MAX_VERSION_LEAD_SECS: u64 = 24 * 60 * 60;

#[derive(Clone)]
pub struct ScopeCatalogs {
	callers: ServiceCallers,
	catalogs: Arc<dyn ScopeCatalogRepository>,
}

impl ScopeCatalogs {
	pub fn new(callers: ServiceCallers, catalogs: Arc<dyn ScopeCatalogRepository>) -> Self {
		Self { callers, catalogs }
	}
}

fn now_secs() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn unavailable(err: domain::error::DomainError) -> Status {
	tracing::error!("scope catalog store failed: {err}");
	Status::unavailable("internal error")
}

fn level_from(raw: i32) -> Result<ApprovalLevel, String> {
	match cc::ApprovalLevel::try_from(raw) {
		Ok(cc::ApprovalLevel::Platform) => Ok(ApprovalLevel::Platform),
		Ok(cc::ApprovalLevel::Scope) => Ok(ApprovalLevel::Scope),
		Ok(cc::ApprovalLevel::Unspecified) | Err(_) => Err("an approval kind names its level".into()),
	}
}

fn field_type_from(raw: i32) -> Result<FieldType, String> {
	match cc::ApprovalFieldType::try_from(raw) {
		Ok(cc::ApprovalFieldType::Text) => Ok(FieldType::Text),
		Ok(cc::ApprovalFieldType::Amount) => Ok(FieldType::Amount),
		Ok(cc::ApprovalFieldType::Bps) => Ok(FieldType::Bps),
		Ok(cc::ApprovalFieldType::Flag) => Ok(FieldType::Flag),
		Ok(cc::ApprovalFieldType::User) => Ok(FieldType::User),
		Ok(cc::ApprovalFieldType::Timestamp) => Ok(FieldType::Timestamp),
		Ok(cc::ApprovalFieldType::Count) => Ok(FieldType::Count),
		Ok(cc::ApprovalFieldType::Unspecified) | Err(_) => Err("a field type is one this plane can render".into()),
	}
}

fn test_from(raw: i32) -> Result<EscalationTest, String> {
	match cc::EscalationTest::try_from(raw) {
		Ok(cc::EscalationTest::AmountAbove) => Ok(EscalationTest::AmountAbove),
		Ok(cc::EscalationTest::Rolling24hAmountAbove) => Ok(EscalationTest::Rolling24hAmountAbove),
		Ok(cc::EscalationTest::AbsBpsAbove) => Ok(EscalationTest::AbsBpsAbove),
		Ok(cc::EscalationTest::FlagSet) => Ok(EscalationTest::FlagSet),
		Ok(cc::EscalationTest::CountAbove) => Ok(EscalationTest::CountAbove),
		Ok(cc::EscalationTest::Rolling24hCountAbove) => Ok(EscalationTest::Rolling24hCountAbove),
		Ok(cc::EscalationTest::Unspecified) | Err(_) => Err("an escalation names its test".into()),
	}
}

fn kind_from(spec: ApprovalKindSpec) -> Result<ApprovalKind, String> {
	Ok(ApprovalKind {
		level: level_from(spec.level)?,
		fields: spec
			.fields
			.into_iter()
			.map(|f| {
				Ok(FieldSpec {
					field_type: field_type_from(f.r#type)?,
					key: f.key,
					label: f.label,
					required: f.required,
					// A published kind cannot ask for a repeatable field; only this plane's own do.
					repeated: false,
				})
			})
			.collect::<Result<_, String>>()?,
		escalations: spec
			.escalations
			.into_iter()
			.map(|e| {
				Ok(Escalation {
					test: test_from(e.test)?,
					parameter: e.parameter,
					field_key: e.field_key,
					default_threshold: e.default_threshold,
					currency: e.currency,
				})
			})
			.collect::<Result<_, String>>()?,
		name: spec.name,
		label: spec.label,
		description: spec.description,
	})
}

pub(crate) fn kind_to(kind: ApprovalKind, proposer: &str) -> ApprovalKindSpec {
	ApprovalKindSpec {
		name: kind.name,
		label: kind.label,
		description: kind.description,
		level: match kind.level {
			ApprovalLevel::Platform => cc::ApprovalLevel::Platform,
			ApprovalLevel::Scope => cc::ApprovalLevel::Scope,
		} as i32,
		fields: kind
			.fields
			.into_iter()
			.map(|f| ApprovalFieldSpec {
				key: f.key,
				label: f.label,
				r#type: match f.field_type {
					FieldType::Text => cc::ApprovalFieldType::Text,
					FieldType::Amount => cc::ApprovalFieldType::Amount,
					FieldType::Bps => cc::ApprovalFieldType::Bps,
					FieldType::Flag => cc::ApprovalFieldType::Flag,
					FieldType::User => cc::ApprovalFieldType::User,
					FieldType::Timestamp => cc::ApprovalFieldType::Timestamp,
					FieldType::Count => cc::ApprovalFieldType::Count,
				} as i32,
				required: f.required,
			})
			.collect(),
		escalations: kind
			.escalations
			.into_iter()
			.map(|e| ApprovalEscalation {
				parameter: e.parameter,
				field_key: e.field_key,
				test: match e.test {
					EscalationTest::AmountAbove => cc::EscalationTest::AmountAbove,
					EscalationTest::Rolling24hAmountAbove => cc::EscalationTest::Rolling24hAmountAbove,
					EscalationTest::AbsBpsAbove => cc::EscalationTest::AbsBpsAbove,
					EscalationTest::FlagSet => cc::EscalationTest::FlagSet,
					EscalationTest::CountAbove => cc::EscalationTest::CountAbove,
					EscalationTest::Rolling24hCountAbove => cc::EscalationTest::Rolling24hCountAbove,
				} as i32,
				default_threshold: e.default_threshold,
				currency: e.currency,
			})
			.collect(),
		proposer: proposer.to_owned(),
	}
}

#[tonic::async_trait]
impl ScopeCatalogService for ScopeCatalogs {
	async fn publish_scope_catalog(&self, request: Request<PublishScopeCatalogRequest>) -> Result<Response<PublishScopeCatalogResponse>, Status> {
		let caller = self.callers.authenticate(&request, "scope catalog").await?;
		if let ServiceCaller::Client(client) = &caller
			&& client.scope_closed
		{
			return Err(Status::failed_precondition("the scope is closed: nothing new is accepted from it"));
		}
		let namespace = caller.namespace().to_owned();
		let req = request.into_inner();
		if req.version == 0 {
			return Err(Status::invalid_argument(
				"version is the unix seconds of the build commit; 0 is this plane's own built-in catalog",
			));
		}
		if req.version > now_secs() + MAX_VERSION_LEAD_SECS {
			return Err(Status::invalid_argument(format!(
				"version {} is more than a day ahead of this plane's clock: it is the unix seconds of the build's commit",
				req.version
			)));
		}
		let catalog = ScopeCatalog {
			version: req.version,
			approval_kinds: req.approval_kinds.into_iter().map(kind_from).collect::<Result<_, _>>().map_err(Status::invalid_argument)?,
			notification_topics: req
				.notification_topics
				.into_iter()
				.map(|t: NotificationTopicSpec| NotificationTopic {
					topic: t.topic,
					label: t.label,
					description: t.description,
					default_subscribed: t.default_subscribed,
				})
				.collect(),
		};
		let reserved: Vec<&str> = TOPICS.iter().map(|t| t.key).collect();
		catalog.check(&namespace, &reserved).map_err(Status::invalid_argument)?;
		let now = now_secs() as i64;
		match self.catalogs.publish(&namespace, caller.publisher(), &catalog, now).await.map_err(unavailable)? {
			PublishOutcome::Published => tracing::info!(%namespace, publisher = caller.publisher(), version = catalog.version, "scope catalog published"),
			PublishOutcome::Unchanged => {}
			PublishOutcome::Stale { stored } => {
				tracing::warn!(%namespace, publisher = caller.publisher(), version = catalog.version, stored, "stale scope catalog refused");
				return Err(Status::failed_precondition(format!("version {} does not supersede the stored {stored}", catalog.version)));
			}
		}
		Ok(Response::new(PublishScopeCatalogResponse {}))
	}

	async fn get_scope_catalog(&self, request: Request<GetScopeCatalogRequest>) -> Result<Response<cc::ScopeCatalog>, Status> {
		let caller = self.callers.authenticate(&request, "scope catalog").await?;
		let namespace = caller.namespace();
		let catalog = self
			.catalogs
			.current(namespace)
			.await
			.map_err(unavailable)?
			.ok_or_else(|| Status::not_found("nothing published yet"))?;
		Ok(Response::new(cc::ScopeCatalog {
			namespace: namespace.to_owned(),
			version: catalog.version,
			approval_kinds: catalog.approval_kinds.into_iter().map(|k| kind_to(k, namespace)).collect(),
			notification_topics: catalog
				.notification_topics
				.into_iter()
				.map(|t| NotificationTopicSpec {
					topic: t.topic,
					label: t.label,
					description: t.description,
					default_subscribed: t.default_subscribed,
				})
				.collect(),
		}))
	}
}
