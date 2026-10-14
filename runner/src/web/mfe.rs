//! The platform's micro-frontend bundles (`web/dist`), served under `/auth/mfe/*` from
//! the directory `WEB_MFE_DIR` names (`docs/SCOPES-AND-APPROVALS.md` §3.1, the plan's
//! §4.1/§4.3: hosts load them by manifest and allow this origin in their CSP).
//!
//! The serving itself — conditional requests (ETag, Last-Modified, 304), ranges, the
//! content type — is tower-http's `ServeDir`. What is decided here is what it may be
//! asked for: files only, no index, no listing, nothing outside the directory. A path
//! segment that could climb out of it (`..`, `.`, a dotfile, a backslash) or a symlink
//! that resolves outside it answers 404, the same as a file that is not there — checked
//! here because `ServeDir` follows symlinks wherever they point. GET and HEAD only.
//! Read-only and public, so CORS answers a scope's origin without credentials: a host
//! fetches the manifest and the bundles anonymously.

use std::{
	path::{Path, PathBuf},
	sync::Arc,
};

use axum::{
	Router,
	extract::{Path as UrlPath, Request, State},
	http::{
		HeaderValue, StatusCode, Uri,
		header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE, ORIGIN, VARY, X_CONTENT_TYPE_OPTIONS},
	},
	response::{IntoResponse, Response},
	routing::get,
};
use color_eyre::eyre::{Context, Result, ensure};
use tower::ServiceExt;
use tower_http::services::ServeDir;

use crate::web::allowlist::SignInAllowlist;

/// The manifest hosts read to find the current bundles. It names hashed files, so it is
/// the one thing that must go stale quickly.
pub const MANIFEST: &str = "registry.json";

const PREFIX: &str = "/auth/mfe";
const SHORT_CACHE: &str = "public, max-age=300";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

pub struct MfeAssets {
	root: PathBuf,
	files: ServeDir,
	allowlist: Arc<SignInAllowlist>,
}

impl MfeAssets {
	/// The directory, resolved once so every request is checked against its real path.
	pub fn open(dir: &Path, allowlist: Arc<SignInAllowlist>) -> Result<Self> {
		let root = std::fs::canonicalize(dir).with_context(|| format!("WEB_MFE_DIR {} cannot be resolved", dir.display()))?;
		ensure!(root.is_dir(), "WEB_MFE_DIR {} is not a directory", root.display());
		let files = ServeDir::new(&root).append_index_html_on_directories(false);
		Ok(Self { root, files, allowlist })
	}
}

/// Add `/auth/mfe/{*path}` to the auth surface.
pub fn mount(router: Router, assets: MfeAssets) -> Router {
	router.merge(Router::new().route("/auth/mfe/{*path}", get(serve)).with_state(Arc::new(assets)))
}

async fn serve(State(assets): State<Arc<MfeAssets>>, UrlPath(path): UrlPath<String>, mut request: Request) -> Response {
	let origin = request.headers().get(ORIGIN).cloned();
	let mut response = match serveable(&assets.root, &path).await {
		Some(name) => {
			// `ServeDir` sees the path below the mount, still percent-encoded: it decodes
			// it itself, to the same file just checked.
			let rest = request.uri().path().strip_prefix(PREFIX).unwrap_or("/").to_owned();
			match Uri::try_from(rest) {
				Ok(uri) => *request.uri_mut() = uri,
				Err(_) => return StatusCode::NOT_FOUND.into_response(),
			}
			let response = match assets.files.clone().oneshot(request).await {
				Ok(response) => response.into_response(),
				Err(never) => match never {},
			};
			describe(response, &name)
		}
		None => StatusCode::NOT_FOUND.into_response(),
	};
	let headers = response.headers_mut();
	headers.append(VARY, HeaderValue::from_static("Origin"));
	if let Some(origin) = origin
		&& let Ok(raw) = origin.to_str()
		&& assets.allowlist.current().await.origins.admits(raw)
	{
		headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
	}
	response
}

/// Lifetime and type for what `ServeDir` answered about `name`.
fn describe(mut response: Response, name: &str) -> Response {
	let status = response.status();
	let headers = response.headers_mut();
	if matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT | StatusCode::NOT_MODIFIED) {
		headers.insert(CACHE_CONTROL, HeaderValue::from_static(if is_hashed(name) { IMMUTABLE } else { SHORT_CACHE }));
		if status != StatusCode::NOT_MODIFIED && matches!(extension(name), Some("js" | "mjs")) {
			headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
		}
	}
	headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
	response
}

/// The file name `path` names under `root`, or `None` for anything that is not a regular
/// file inside it.
async fn serveable(root: &Path, path: &str) -> Option<String> {
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
	segments.last().map(|s| (*s).to_owned())
}

fn is_plain_segment(segment: &str) -> bool {
	!segment.is_empty() && !segment.starts_with('.') && !segment.contains(['\\', '\0'])
}

fn extension(name: &str) -> Option<&str> {
	name.rsplit_once('.').map(|(_, ext)| ext)
}

/// Whether the name is esbuild's `<name>-<HASH>.<ext>`: eight characters of `A-Z0-9`
/// directly before the one extension. Only then can its bytes never change under the
/// name; anything else (the manifest, `LICENSES.txt`, a source map `x-HASH.js.map`) gets
/// the short lifetime — a missed hash costs a revalidation, a false one pins a stale file
/// in browsers for a year.
fn is_hashed(name: &str) -> bool {
	let Some((stem, ext)) = name.rsplit_once('.') else {
		return false;
	};
	let Some((base, hash)) = stem.rsplit_once('-') else {
		return false;
	};
	!base.is_empty() && !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_alphanumeric()) && hash.len() == 8 && hash.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_esbuild_hashed_names_are_immutable() {
		for hashed in ["sign-in-ABCD2345.js", "chunk-Q7ZK3M2P.js", "index-ABCD2345.css", "a-ZZZZZZZZ.woff2"] {
			assert!(is_hashed(hashed), "{hashed}");
		}
		for plain in [
			MANIFEST,
			"MANIFEST.json",
			"LICENSES.txt",
			"sign-in.js",
			"Settings.js",
			"sign-in-ABCD2345.js.map",
			"app.3f9a1c0b.js",
			"sign-in-abcd2345.js",
			"sign-in-ABCD234.js",
			"-ABCD2345.js",
			"ABCD2345",
			"sign-in-ABCD2345",
		] {
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
