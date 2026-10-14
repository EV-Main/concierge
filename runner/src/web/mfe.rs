//! The platform's micro-frontend bundles (`web/dist`), served under `/auth/mfe/*` from
//! the directory `WEB_MFE_DIR` names (`docs/SCOPES-AND-APPROVALS.md` §3.1, the plan's
//! §4.1/§4.3: hosts load them by manifest and allow this origin in their CSP).
//!
//! Files only: no index, no listing, nothing outside the directory — a path segment that
//! could climb out of it (`..`, `.`, a dotfile, a backslash) or a symlink that resolves
//! outside it answers 404, the same as a file that is not there. GET and HEAD only.
//! Read-only and public, so CORS answers a scope's origin without credentials: a host
//! fetches the manifest and the bundles anonymously.

use std::{
	path::{Path, PathBuf},
	sync::Arc,
};

use axum::{
	Router,
	extract::{Path as UrlPath, State},
	http::{
		HeaderMap, HeaderValue, StatusCode,
		header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE, ORIGIN, VARY, X_CONTENT_TYPE_OPTIONS},
	},
	response::{IntoResponse, Response},
	routing::get,
};
use color_eyre::eyre::{Context, Result, ensure};

use crate::web::origins::ScopeOrigins;

/// The manifest hosts read to find the current bundles. It names hashed files, so it is
/// the one thing that must go stale quickly.
pub const MANIFEST: &str = "registry.json";

const SHORT_CACHE: &str = "public, max-age=300";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub struct MfeAssets {
	root: PathBuf,
	origins: ScopeOrigins,
}

impl MfeAssets {
	/// The directory, resolved once so every request is checked against its real path.
	pub fn open(dir: &Path, origins: ScopeOrigins) -> Result<Self> {
		let root = std::fs::canonicalize(dir).with_context(|| format!("WEB_MFE_DIR {} cannot be resolved", dir.display()))?;
		ensure!(root.is_dir(), "WEB_MFE_DIR {} is not a directory", root.display());
		Ok(Self { root, origins })
	}
}

/// Add `/auth/mfe/{*path}` to the auth surface.
pub fn mount(router: Router, assets: MfeAssets) -> Router {
	router.merge(Router::new().route("/auth/mfe/{*path}", get(serve)).with_state(Arc::new(assets)))
}

async fn serve(State(assets): State<Arc<MfeAssets>>, UrlPath(path): UrlPath<String>, headers: HeaderMap) -> Response {
	let mut response = match read(&assets.root, &path).await {
		Some((name, body)) => {
			let mut response = body.into_response();
			let h = response.headers_mut();
			h.insert(CONTENT_TYPE, HeaderValue::from_static(content_type(&name)));
			h.insert(CACHE_CONTROL, HeaderValue::from_static(if is_hashed(&name) { IMMUTABLE } else { SHORT_CACHE }));
			h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
			response
		}
		None => StatusCode::NOT_FOUND.into_response(),
	};
	let h = response.headers_mut();
	h.append(VARY, HeaderValue::from_static("Origin"));
	if let Some(origin) = headers.get(ORIGIN).filter(|o| o.to_str().is_ok_and(|o| assets.origins.admits(o))) {
		h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
	}
	response
}

/// The file `path` names under `root`, or `None` for anything that is not a regular file
/// inside it. A read error is logged and answered as absent: the caller is a browser
/// that can do nothing with the difference.
async fn read(root: &Path, path: &str) -> Option<(String, Vec<u8>)> {
	let segments: Vec<&str> = path.split('/').collect();
	if !segments.iter().all(|s| is_plain_segment(s)) {
		return None;
	}
	let candidate = segments.iter().fold(root.to_path_buf(), |p, s| p.join(s));
	// A symlink inside the directory may point anywhere; only where it RESOLVES counts.
	let resolved = tokio::fs::canonicalize(&candidate).await.ok()?;
	if !resolved.starts_with(root) || !tokio::fs::metadata(&resolved).await.ok()?.is_file() {
		return None;
	}
	match tokio::fs::read(&resolved).await {
		Ok(body) => Some(((*segments.last()?).to_owned(), body)),
		Err(e) => {
			tracing::error!(path = %resolved.display(), error = %e, "mfe asset not read");
			None
		}
	}
}

fn is_plain_segment(segment: &str) -> bool {
	!segment.is_empty() && !segment.starts_with('.') && !segment.contains(['\\', '\0'])
}

fn content_type(name: &str) -> &'static str {
	match name.rsplit_once('.').map(|(_, ext)| ext) {
		Some("js" | "mjs") => "text/javascript; charset=utf-8",
		Some("css") => "text/css; charset=utf-8",
		Some("json" | "map") => "application/json",
		Some("html") => "text/html; charset=utf-8",
		Some("svg") => "image/svg+xml",
		Some("png") => "image/png",
		Some("webp") => "image/webp",
		Some("ico") => "image/x-icon",
		Some("woff2") => "font/woff2",
		Some("woff") => "font/woff",
		Some("wasm") => "application/wasm",
		Some("txt") => "text/plain; charset=utf-8",
		_ => "application/octet-stream",
	}
}

/// Whether the name carries a content hash (esbuild's `[name]-[hash]`, 8 characters of
/// `A-Z0-9`, or a lowercase hex digest), so its bytes can never change under it. Anything
/// unrecognised gets the short lifetime: a missed hash costs a revalidation, a false one
/// pins a stale file in browsers for a year.
fn is_hashed(name: &str) -> bool {
	if name == MANIFEST {
		return false;
	}
	let mut tokens: Vec<&str> = name.split(['-', '.']).collect();
	tokens.pop();
	tokens.iter().any(|t| {
		(8..=64).contains(&t.len())
			&& t.bytes().all(|b| b.is_ascii_alphanumeric())
			&& (t.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
				|| (t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) && t.bytes().any(|b| b.is_ascii_digit())))
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_content_hashed_names_are_immutable() {
		for hashed in ["sign-in-ABCD2345.js", "chunk-Q7ZK3M2P.js", "index-ABCD2345.css", "sign-in-ABCD2345.js.map", "app.3f9a1c0b.js"] {
			assert!(is_hashed(hashed), "{hashed}");
		}
		for plain in [MANIFEST, "sign-in.js", "settings.js", "Settings.js", "favicon.ico", "registry-v2.json", "ABCD2345"] {
			assert!(!is_hashed(plain), "{plain}");
		}
	}

	#[test]
	fn a_segment_that_could_leave_the_directory_is_refused() {
		for bad in ["", ".", "..", ".env", "a\\b", "a\0b"] {
			assert!(!is_plain_segment(bad), "{bad:?}");
		}
		assert!(is_plain_segment("sign-in-ABCD2345.js"));
	}
}
