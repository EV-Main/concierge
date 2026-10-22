//! The platform's micro-frontend bundles (`web/dist`), served under `/auth/mfe/*` —
//! publicly `/api/auth/mfe/*` — from the directory `WEB_MFE_DIR` names
//! (`docs/SCOPES-AND-APPROVALS.md` §3.1). Hosts find the current bundles through the
//! manifest, [`MANIFEST`].
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
		header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN, REFERRER_POLICY, VARY, X_CONTENT_TYPE_OPTIONS},
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
	// Resolved once, so every request is checked against the directory's real path.
	pub fn open(dir: &Path, allowlist: Arc<SignInAllowlist>) -> Result<Self> {
		let root = std::fs::canonicalize(dir).with_context(|| format!("WEB_MFE_DIR {} cannot be resolved", dir.display()))?;
		ensure!(root.is_dir(), "WEB_MFE_DIR {} is not a directory", root.display());
		let files = ServeDir::new(&root).append_index_html_on_directories(false);
		Ok(Self { root, files, allowlist })
	}
}

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
		&& assets.allowlist.current().origins.admits(raw)
	{
		headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
	}
	response
}

/// What a page here may load: its own bundles and the plane's routes, Turnstile (the
/// re-authentication code asks for a human), and the inline `<style>` the elements insert
/// and the `style` attributes React writes — hence `'unsafe-inline'` for styles, never for
/// scripts. `data:` images are the tokens' inline brand mark.
const PAGE_CSP: &str = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; \
	style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'";

fn describe(mut response: Response, name: &str) -> Response {
	let status = response.status();
	let headers = response.headers_mut();
	if matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT | StatusCode::NOT_MODIFIED) {
		headers.insert(CACHE_CONTROL, HeaderValue::from_static(if is_hashed(name) { IMMUTABLE } else { SHORT_CACHE }));
		if status != StatusCode::NOT_MODIFIED && matches!(extension(name), Some("js" | "mjs")) {
			headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
		}
	}
	// A page here is a platform page that asks for a password, a code or a passkey (the
	// confirmation `web::authorize` sends a browser to): never framed, never cached, and its
	// URL — which carries a client's authorize request — never sent on as a Referer.
	if matches!(extension(name), Some("html")) {
		headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
		headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(PAGE_CSP));
		headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
	}
	headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
	response
}

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
	fn a_page_is_never_framed_cached_or_referred() {
		let page = describe(StatusCode::OK.into_response(), "reauth.html");
		assert_eq!(page.headers()[CACHE_CONTROL], "no-store");
		let csp = page.headers()[CONTENT_SECURITY_POLICY].to_str().unwrap();
		for directive in [
			"default-src 'self'",
			"base-uri 'none'",
			"object-src 'none'",
			"frame-ancestors 'none'",
			"script-src 'self' https://challenges.cloudflare.com;",
		] {
			assert!(csp.contains(directive), "{directive} in {csp}");
		}
		assert!(!csp.contains("script-src 'self' 'unsafe-inline'"), "no inline script: {csp}");
		assert_eq!(page.headers()[REFERRER_POLICY], "no-referrer");
		let bundle = describe(StatusCode::OK.into_response(), "reauth-ABCD2345.js");
		assert_eq!(bundle.headers()[CACHE_CONTROL], IMMUTABLE);
		assert!(bundle.headers().get(CONTENT_SECURITY_POLICY).is_none());
	}

	#[test]
	fn a_segment_that_could_leave_the_directory_is_refused() {
		for bad in ["", ".", "..", ".env", "a\\b", "a\0b"] {
			assert!(!is_plain_segment(bad), "{bad:?}");
		}
		assert!(is_plain_segment("sign-in-ABCD2345.js"));
	}
}
