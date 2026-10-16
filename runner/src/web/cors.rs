//! CORS for the sign-in routes a scope's hosts call.
//!
//! The scope hosts are same-site with the public origin, so the session cookies ride
//! these requests already; CORS only decides whether the calling page may READ the
//! answer. Hence credentials are allowed and the allowed origin is echoed exactly —
//! never `*`, which a browser refuses beside credentials anyway — with `Vary: Origin`.
//! Mounted on the listed routes alone (`router`); no other route gets a CORS header from it.
//! `/auth/mfe/*` sets its own, credential-less (`web::mfe`).

use std::{sync::Arc, time::Duration};

use axum::http::{Method, header::CONTENT_TYPE};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::web::allowlist::SignInAllowlist;

/// How long a browser may reuse a preflight. A cached approval for a scope closed since
/// still meets the `Origin` check on the request itself, and an answer without
/// `Access-Control-Allow-Origin` the page cannot read.
const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(600);

pub(super) fn layer(allowlist: Arc<SignInAllowlist>, method: Method) -> CorsLayer {
	// A plain predicate, not `async_predicate`: the allowlist answers from the snapshot in
	// hand and never waits on the database.
	CorsLayer::new()
		.allow_origin(AllowOrigin::predicate(move |origin, _| origin.to_str().is_ok_and(|o| allowlist.admits(o))))
		.allow_credentials(true)
		.allow_methods([method])
		.allow_headers([CONTENT_TYPE])
		.max_age(PREFLIGHT_MAX_AGE)
}
