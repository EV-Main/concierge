//! Sign-in from a scope's hosts (`docs/SCOPES-AND-APPROVALS.md` §3.1): which foreign
//! origins the sign-in routes answer, and where an OAuth sign-in may land on them.
//!
//! Kept current by `allowlist::SignInAllowlist`, which rebuilds a [`ScopeOrigins`] from
//! the registry.

use domain::scopes::{is_return_path, is_sign_in_origin};

use crate::ports::ScopeRecord;

/// Exact path + method of every route a scope origin may call. Closed on purpose: a
/// route acting on an open session (email verification, password set, passkey
/// register/remove, sessions, username, logout, `/kyc/*`) answers `PUBLIC_ORIGIN` alone,
/// so a script on a scope's host can start a sign-in but never act for the account it
/// signed in. Those routes carry the CSRF double-submit, whose cookie a scope host cannot
/// read anyway; listing them would only promise a flow that cannot complete. A scope host
/// proves a mailbox by signing in with a code (`/auth/code/request` + `verify`).
pub(super) const SIGN_IN_ROUTES: &[SignInRoute] = &[
	SignInRoute::post("/auth/code/request"),
	SignInRoute::post("/auth/code/verify"),
	SignInRoute::post("/auth/password/signin"),
	SignInRoute::post("/auth/password/signup"),
	SignInRoute::post("/auth/passkey/signin/options"),
	SignInRoute::post("/auth/passkey/signin/verify"),
	SignInRoute {
		path: "/auth/session",
		method: "GET",
		request_headers: "",
	},
];

pub(super) struct SignInRoute {
	pub(super) path: &'static str,
	pub(super) method: &'static str,
	/// What a preflight may announce in `Access-Control-Request-Headers`.
	pub(super) request_headers: &'static str,
}

impl SignInRoute {
	const fn post(path: &'static str) -> Self {
		Self {
			path,
			method: "POST",
			request_headers: "content-type",
		}
	}
}

pub(super) fn sign_in_route(path: &str) -> Option<&'static SignInRoute> {
	SIGN_IN_ROUTES.iter().find(|route| route.path == path)
}

/// The origins of every scope that still signs people in, each with the paths an OAuth
/// sign-in may land on there.
#[derive(Clone, Debug, Default)]
pub struct ScopeOrigins {
	scopes: Vec<ScopeHosts>,
}

#[derive(Clone, Debug)]
struct ScopeHosts {
	origins: Vec<String>,
	return_paths: Vec<String>,
}

impl ScopeOrigins {
	/// Nothing but `PUBLIC_ORIGIN` is answered.
	pub fn none() -> Self {
		Self::default()
	}

	/// Closed scopes are left out, and so is any origin or path that breaks the shape
	/// rules — the CHECKs refuse such a row, so meeting one here means somebody bypassed
	/// them, and the answer to that is to trust it less, not to stop signing everyone in.
	pub fn from_scopes(scopes: &[ScopeRecord]) -> Self {
		let scopes = scopes
			.iter()
			.filter(|scope| scope.state.signs_in())
			.map(|scope| {
				let keep = |what: &str, value: &String, valid: fn(&str) -> bool| {
					let ok = valid(value);
					if !ok {
						tracing::error!(scope = %scope.id, value = %value, "scope registry holds a malformed {what}; ignored");
					}
					ok
				};
				ScopeHosts {
					origins: scope.origins.iter().filter(|o| keep("origin", o, is_sign_in_origin)).cloned().collect(),
					return_paths: scope.return_paths.iter().filter(|p| keep("return path", p, is_return_path)).cloned().collect(),
				}
			})
			.collect();
		Self { scopes }
	}

	/// Whether `origin` is, byte for byte, one of a signing-in scope's origins.
	pub fn admits(&self, origin: &str) -> bool {
		self.origins().any(|o| o == origin)
	}

	pub fn origins(&self) -> impl Iterator<Item = &str> {
		self.scopes.iter().flat_map(|s| s.origins.iter().map(String::as_str))
	}

	/// Whether `raw` is exactly a scope origin followed by one of THAT scope's return
	/// paths. Nothing else absolute is a sign-in's landing, so `returnTo` is never an open
	/// redirect.
	pub fn is_return_target(&self, raw: &str) -> bool {
		self.scopes.iter().any(|scope| {
			scope
				.origins
				.iter()
				.any(|origin| raw.strip_prefix(origin.as_str()).is_some_and(|path| scope.return_paths.iter().any(|p| p == path)))
		})
	}
}

#[cfg(test)]
mod tests {
	use domain::scopes::ScopeState;

	use super::*;

	fn scope(id: &str, state: ScopeState, origins: &[&str], paths: &[&str]) -> ScopeRecord {
		ScopeRecord {
			id: id.into(),
			namespace: id.into(),
			parent: "main".into(),
			display_name: String::new(),
			origins: origins.iter().map(|s| (*s).to_owned()).collect(),
			return_paths: paths.iter().map(|s| (*s).to_owned()).collect(),
			observers: Vec::new(),
			clients: Vec::new(),
			created_at: 0,
			version: 1,
			state,
		}
	}

	fn registry() -> ScopeOrigins {
		ScopeOrigins::from_scopes(&[
			scope("invest", ScopeState::Active, &["https://invest.evinvest.ltd"], &["/cabinet"]),
			scope("sa", ScopeState::Frozen, &["https://sa.evinvest.ltd"], &["/"]),
			scope("old", ScopeState::Closed, &["https://old.evinvest.ltd"], &["/"]),
			scope("bad", ScopeState::Active, &["http://bad.evinvest.ltd", "https://good.evinvest.ltd"], &["//evil", "/ok"]),
		])
	}

	#[test]
	fn origins_match_byte_for_byte_and_closed_scopes_drop_out() {
		let o = registry();
		assert!(o.admits("https://invest.evinvest.ltd"));
		assert!(o.admits("https://sa.evinvest.ltd"), "a frozen scope still signs people in");
		assert!(!o.admits("https://old.evinvest.ltd"), "a closed scope signs nobody in");
		assert!(!o.admits("http://bad.evinvest.ltd"), "a malformed stored origin is ignored");
		assert!(o.admits("https://good.evinvest.ltd"));
		for bad in [
			"https://invest.evinvest.ltd/",
			"https://INVEST.evinvest.ltd",
			"https://invest.evinvest.ltd.evil.com",
			"https://evil.com/https://invest.evinvest.ltd",
			"null",
			"",
		] {
			assert!(!o.admits(bad), "{bad}");
		}
	}

	#[test]
	fn a_return_target_is_an_origin_plus_one_of_its_own_paths() {
		let o = registry();
		assert!(o.is_return_target("https://invest.evinvest.ltd/cabinet"));
		assert!(o.is_return_target("https://sa.evinvest.ltd/"));
		assert!(o.is_return_target("https://good.evinvest.ltd/ok"));
		for bad in [
			"https://invest.evinvest.ltd/",
			"https://invest.evinvest.ltd/cabinet/",
			"https://invest.evinvest.ltd/cabinet?next=x",
			"https://invest.evinvest.ltd/cabinetx",
			"https://sa.evinvest.ltd/cabinet",
			"https://old.evinvest.ltd/",
			"https://good.evinvest.ltd//evil",
			"https://evil.com/cabinet",
			"https://invest.evinvest.ltd",
		] {
			assert!(!o.is_return_target(bad), "{bad}");
		}
	}

	#[test]
	fn the_route_list_is_closed() {
		assert!(sign_in_route("/auth/session").is_some_and(|r| r.method == "GET"));
		for acting in [
			"/auth/email/verify/request",
			"/auth/email/verify/confirm",
			"/auth/password/set",
			"/auth/passkey/register/options",
			"/auth/passkey/remove",
			"/auth/sessions",
			"/auth/username",
			"/auth/logout",
			"/auth/methods",
			"/kyc/start",
			"/kyc/status",
			"/auth/login",
		] {
			assert!(sign_in_route(acting).is_none(), "{acting}");
		}
	}
}
