//! Scopes — a tenant seen as a direction (`docs/SCOPES-AND-APPROVALS.md` §3).
//!
//! The shape rules for a scope's `origins` and `return_paths` live here as well as in the
//! `tenants` CHECKs (migration 0031): they decide which foreign origin may sign a browser
//! in and where a sign-in may land, so a row that slipped past one copy must still be
//! refused by the other before anything trusts it.

use crate::error::DomainError;

/// The implicit root scope. It has no tenant row and no namespace of its own.
pub const ROOT: &str = "main";

/// The registrable domain every scope origin must sit under. Same-site with the public
/// origin is what lets the session cookie ride a cross-origin sign-in request at all.
pub const SITE: &str = "evinvest.ltd";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeState {
	Active,
	/// Reversibly stopped; its clients still sign people in, because a direction has to
	/// learn it was frozen.
	Frozen,
	/// Terminal: its clients and origins sign nobody in.
	Closed,
}

impl ScopeState {
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		match raw {
			"active" => Ok(Self::Active),
			"frozen" => Ok(Self::Frozen),
			"closed" => Ok(Self::Closed),
			other => Err(DomainError::Validation(format!("unknown scope state `{other}`"))),
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Active => "active",
			Self::Frozen => "frozen",
			Self::Closed => "closed",
		}
	}

	/// Whether the scope's origins may still start a sign-in.
	pub fn signs_in(self) -> bool {
		match self {
			Self::Active | Self::Frozen => true,
			Self::Closed => false,
		}
	}
}

/// An origin exactly as a browser sends `Origin`: `https` only, the host [`SITE`] or a
/// subdomain of it, a port only when non-default, nothing after the authority. No
/// wildcard and never `null` — both fall out of the host rule.
pub fn is_sign_in_origin(raw: &str) -> bool {
	let Some(authority) = raw.strip_prefix("https://") else {
		return false;
	};
	let (host, port) = match authority.split_once(':') {
		Some((host, port)) => (host, Some(port)),
		None => (authority, None),
	};
	if let Some(port) = port {
		let digits = !port.is_empty() && port.len() <= 5 && !port.starts_with('0') && port.bytes().all(|b| b.is_ascii_digit());
		if !digits || port == "443" || port.parse::<u32>().map_or(true, |p| p > u32::from(u16::MAX)) {
			return false;
		}
	}
	host == SITE
		|| host
			.strip_suffix(SITE)
			.and_then(|rest| rest.strip_suffix('.'))
			.is_some_and(|labels| labels.split('.').all(is_dns_label))
}

fn is_dns_label(label: &str) -> bool {
	let bytes = label.as_bytes();
	(1..=63).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') && bytes.first() != Some(&b'-') && bytes.last() != Some(&b'-')
}

/// A path an OAuth `returnTo` may name: `/`, or non-empty segments of URL path
/// characters with no trailing slash. No query and no fragment, because the target is
/// matched byte for byte and a query would make every registered path a prefix.
pub fn is_return_path(raw: &str) -> bool {
	if raw == "/" {
		return true;
	}
	let Some(rest) = raw.strip_prefix('/') else {
		return false;
	};
	rest.split('/').all(|segment| !segment.is_empty() && segment.bytes().all(is_path_byte))
}

fn is_path_byte(b: u8) -> bool {
	b.is_ascii_alphanumeric() || b"._~%!$&'()*+,;=:@-".contains(&b)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn origins_are_https_hosts_under_the_site() {
		for ok in [
			"https://evinvest.ltd",
			"https://invest.evinvest.ltd",
			"https://a-b.c1.evinvest.ltd",
			"https://sa.evinvest.ltd:8443",
		] {
			assert!(is_sign_in_origin(ok), "{ok}");
		}
		for bad in [
			"http://invest.evinvest.ltd",
			"https://invest.evinvest.ltd/",
			"https://invest.evinvest.ltd/cabinet",
			"https://invest.evinvest.ltd:443",
			"https://invest.evinvest.ltd:",
			"https://invest.evinvest.ltd:080",
			"https://invest.evinvest.ltd:99999",
			"https://*.evinvest.ltd",
			"https://xevinvest.ltd",
			"https://evinvest.ltd.evil.com",
			"https://.evinvest.ltd",
			"https://-a.evinvest.ltd",
			"https://INVEST.evinvest.ltd",
			"https://user@invest.evinvest.ltd",
			"null",
			"",
		] {
			assert!(!is_sign_in_origin(bad), "{bad}");
		}
	}

	#[test]
	fn return_paths_are_exact_paths() {
		for ok in ["/", "/cabinet", "/auth/login", "/a/b.c"] {
			assert!(is_return_path(ok), "{ok}");
		}
		for bad in ["", "cabinet", "//evil", "/cabinet/", "/cabinet?x=1", "/cabinet#x", "/a//b", "/a\\b", "/ a"] {
			assert!(!is_return_path(bad), "{bad}");
		}
	}

	#[test]
	fn only_a_closed_scope_stops_signing_in() {
		for state in [ScopeState::Active, ScopeState::Frozen, ScopeState::Closed] {
			assert_eq!(ScopeState::parse(state.as_str()).unwrap(), state);
		}
		assert!(ScopeState::Active.signs_in());
		assert!(ScopeState::Frozen.signs_in());
		assert!(!ScopeState::Closed.signs_in());
	}
}
