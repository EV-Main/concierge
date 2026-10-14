//! CORS for the sign-in routes a scope's hosts call (`origins::SIGN_IN_ROUTES`).
//!
//! The scope hosts are same-site with the public origin, so the session cookies ride
//! these requests already; CORS only decides whether the calling page may READ the
//! answer. Hence credentials are allowed and the allowed origin is echoed exactly —
//! never `*`, which a browser refuses beside credentials anyway — and `Vary: Origin`
//! goes on every answer of a listed route, so a cache never hands one origin's
//! permission to another. Every other route gets no CORS header at all.

use axum::{
	extract::{Request, State},
	http::{
		HeaderMap, HeaderValue, Method, StatusCode,
		header::{
			ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_METHOD,
			ORIGIN, VARY,
		},
	},
	middleware::Next,
	response::{IntoResponse, Response},
};

use crate::web::{WebState, origins::sign_in_route};

/// How long a browser may reuse a preflight. Short: an origin dropped from the registry
/// should stop being answered within minutes of the boot that dropped it.
const PREFLIGHT_MAX_AGE_SECS: &str = "600";

pub(super) async fn sign_in(State(st): State<WebState>, request: Request, next: Next) -> Response {
	let Some(route) = sign_in_route(request.uri().path()) else {
		return next.run(request).await;
	};
	let allowed = request
		.headers()
		.get(ORIGIN)
		.and_then(|v| v.to_str().ok())
		.filter(|origin| st.inner.sign_in_origin(origin))
		.and_then(|origin| HeaderValue::from_str(origin).ok());

	if request.method() == Method::OPTIONS {
		let asked = request.headers().get(ACCESS_CONTROL_REQUEST_METHOD).and_then(|v| v.to_str().ok());
		if let Some(origin) = allowed
			&& asked == Some(route.method)
		{
			let mut response = StatusCode::NO_CONTENT.into_response();
			let headers = response.headers_mut();
			allow(headers, origin);
			headers.insert(ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(route.method));
			if !route.request_headers.is_empty() {
				headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static(route.request_headers));
			}
			headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static(PREFLIGHT_MAX_AGE_SECS));
			headers.append(VARY, HeaderValue::from_static("Origin"));
			return response;
		}
		// Not ours to approve: the router answers (405), with no CORS header, and the
		// browser refuses the real request.
		let mut response = next.run(request).await;
		response.headers_mut().append(VARY, HeaderValue::from_static("Origin"));
		return response;
	}

	let allowed = allowed.filter(|_| request.method().as_str() == route.method);
	let mut response = next.run(request).await;
	let headers = response.headers_mut();
	headers.append(VARY, HeaderValue::from_static("Origin"));
	if let Some(origin) = allowed {
		allow(headers, origin);
	}
	response
}

fn allow(headers: &mut HeaderMap, origin: HeaderValue) {
	headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
	headers.insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
}
