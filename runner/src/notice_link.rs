//! Where a notice's link points (banking#580).
//!
//! An emitter names a cabinet-RELATIVE path, never a host. A notice about a scope's
//! business links to that scope's own cabinet, so the emitter may also name the scope
//! (`EmitRequest.link_scope`), and this plane looks its base up in `NOTICE_LINK_BASES`.
//! The emit stores the finished absolute link, because the inbox row is read by the
//! frontends as it is stored and no column holds the scope. Without a base the link stays
//! relative and the mail joins it onto `CABINET_URL`, as before.
//!
//! The property kept: a mail never links outside `CABINET_URL` or a configured base. The
//! host comes only from this plane's configuration, and the dispatcher re-checks a stored
//! absolute link against the configuration in force when it sends.
//!
//! `Result<_, Status>` is tonic's handler error, so the large-err lint does not apply.
#![allow(clippy::result_large_err)]

use color_eyre::eyre::{Context, bail, ensure};
use domain::scopes::{ROOT, is_scope_name};
use tonic::Status;
use webauthn_rs::prelude::Url;

/// The column CHECK `notifications_link_len` (migration 0008), counted in characters.
const LINK_MAX_CHARS: usize = 512;

/// `NOTICE_LINK_BASES`, parsed: one cabinet base per scope.
#[derive(Clone, Debug, Default)]
pub struct NoticeLinkBases {
	/// `(scope, base)`; a base has no trailing slash. A handful of scopes, so a list.
	bases: Vec<(String, String)>,
}

impl NoticeLinkBases {
	/// Read `scope=base` entries. A malformed entry refuses the boot: a typo here would
	/// otherwise send every notice of that scope to `CABINET_URL` with no sign of why.
	///
	/// A base is an absolute URL with no query, fragment, userinfo or trailing slash. Its
	/// host follows the `STEPUP_PROOF_ORIGINS` rule: in production `https`, no port, and
	/// `PUBLIC_ORIGIN`'s host or a host under it; outside production also loopback. `main`
	/// is refused, because the root scope's cabinet is `CABINET_URL` itself.
	pub fn parse(raw: &[String], public_origin: &str, production: bool) -> color_eyre::Result<Self> {
		let public = Url::parse(public_origin).context("PUBLIC_ORIGIN is not a URL")?;
		let public_host = public.host_str().ok_or_else(|| color_eyre::eyre::eyre!("PUBLIC_ORIGIN has no host"))?.to_owned();
		let mut bases: Vec<(String, String)> = Vec::new();
		for entry in raw.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
			let Some((scope, base)) = entry.split_once('=') else {
				bail!("NOTICE_LINK_BASES entry {entry:?} is not `scope=base`");
			};
			ensure!(is_scope_name(scope), "NOTICE_LINK_BASES entry {entry:?}: {scope:?} is not a scope name ([a-z][a-z0-9_]{{0,31}})");
			ensure!(scope != ROOT, "NOTICE_LINK_BASES entry {entry:?}: the root scope's cabinet is CABINET_URL");
			ensure!(!bases.iter().any(|(s, _)| s == scope), "NOTICE_LINK_BASES names {scope:?} twice");
			ensure!(
				!base.chars().any(|c| c.is_whitespace() || !c.is_ascii_graphic()),
				"NOTICE_LINK_BASES entry {entry:?}: the base must be printable ASCII without whitespace"
			);
			ensure!(!base.contains('*'), "NOTICE_LINK_BASES entry {entry:?}: a pattern is never accepted");
			ensure!(!base.ends_with('/'), "NOTICE_LINK_BASES entry {entry:?}: the base must not end with '/'");
			let url = Url::parse(base).with_context(|| format!("NOTICE_LINK_BASES entry {entry:?}: the base is not an absolute URL"))?;
			ensure!(
				url.username().is_empty() && url.password().is_none() && url.query().is_none() && url.fragment().is_none(),
				"NOTICE_LINK_BASES entry {entry:?}: the base must carry no userinfo, query or fragment"
			);
			// `Url` lowercases the host, drops a default port and resolves dot segments; a
			// base that is not already in that form would not match what it serialises to,
			// and the render-time prefix check compares bytes.
			let canonical = if url.path() == "/" { url.as_str().trim_end_matches('/') } else { url.as_str() };
			ensure!(canonical == base, "NOTICE_LINK_BASES entry {entry:?}: write the base in canonical form ({canonical})");
			let host = url.host_str().unwrap_or_default();
			let under_site = host == public_host || host.ends_with(&format!(".{public_host}"));
			if production {
				ensure!(url.scheme() == "https", "NOTICE_LINK_BASES entry {entry:?} must be https in production");
				ensure!(url.port().is_none(), "NOTICE_LINK_BASES entry {entry:?} must not name a port in production");
				ensure!(under_site, "NOTICE_LINK_BASES entry {entry:?} is outside {public_host}");
			} else {
				let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
				ensure!(
					matches!(url.scheme(), "https" | "http") && (under_site || loopback),
					"NOTICE_LINK_BASES entry {entry:?} is neither loopback nor under {public_host}"
				);
			}
			bases.push((scope.to_owned(), base.to_owned()));
		}
		Ok(Self { bases })
	}

	pub fn base(&self, scope: &str) -> Option<&str> {
		self.bases.iter().find(|(s, _)| s == scope).map(|(_, base)| base.as_str())
	}

	/// The link an emit stores. `link` has passed [`relative_link`] already.
	///
	/// A scope with no base keeps the relative link rather than refusing: the emitter
	/// cannot know this plane's configuration, and `CABINET_URL` is the documented
	/// fallback. Only the NAME's syntax is refused, since no registered scope could ever
	/// carry a malformed one.
	pub fn stored_link(&self, link_scope: &str, link: &str) -> Result<String, Status> {
		if link_scope.is_empty() {
			return Ok(link.to_owned());
		}
		if !is_scope_name(link_scope) {
			return Err(Status::invalid_argument("link_scope must be a scope name ([a-z][a-z0-9_]{0,31})"));
		}
		let Some(base) = self.base(link_scope) else {
			return Ok(link.to_owned());
		};
		let stored = join(base, link);
		if stored.chars().count() > LINK_MAX_CHARS {
			return Err(Status::invalid_argument(format!("link with its scope's base must be at most {LINK_MAX_CHARS} characters")));
		}
		Ok(stored)
	}

	/// The URL a notice mail links to.
	///
	/// A stored absolute link passes through unchanged only while it is under
	/// `cabinet_url` or a base configured NOW, checked at a path boundary. Anything else
	/// that is absolute — its base was removed from the configuration since, or the row
	/// was never composed here — links to `cabinet_url` itself: the old host is not
	/// trusted any longer, and the relative part cannot be recovered without the old
	/// base. A relative link is joined onto `cabinet_url`, as it always was.
	pub fn mail_target(&self, cabinet_url: &str, stored: &str) -> String {
		let cabinet = cabinet_url.trim_end_matches('/');
		if !is_absolute(stored) {
			return join(cabinet, stored);
		}
		let trusted = std::iter::once(cabinet)
			.chain(self.bases.iter().map(|(_, base)| base.as_str()))
			.any(|base| is_under(base, stored));
		if trusted {
			return stored.to_owned();
		}
		tracing::warn!(link = stored, "a stored notice link is under no configured cabinet base; the mail links to CABINET_URL");
		cabinet.to_owned()
	}
}

/// The emitter-side rule: a cabinet-relative path, or none. A host is this plane's to
/// choose (`link_scope`), so anything a browser would read as leaving the path — a
/// scheme, `//host`, a backslash that browsers turn into `/` — is refused. Whitespace and
/// control characters are refused too: the mail's text part prints the link bare on its
/// own line, and a newline there would add a second, foreign line.
pub fn relative_link(raw: &str) -> Result<(), Status> {
	if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
		return Err(Status::invalid_argument("link must not contain whitespace or control characters"));
	}
	if is_absolute(raw) {
		return Err(Status::invalid_argument("link must be a cabinet-relative path; name the scope in link_scope for another cabinet"));
	}
	Ok(())
}

/// What a browser resolves to another host or scheme: a scheme before the first `/`, `?`
/// or `#` (RFC 3986 §4.2 forbids a `:` in a relative path's first segment for this
/// reason), a leading `//`, or a backslash anywhere in the leading slashes.
fn is_absolute(raw: &str) -> bool {
	let head = raw.split(['/', '?', '#']).next().unwrap_or_default();
	head.contains(':') || raw.trim_start_matches(['/', '\\']).len() + 1 < raw.len() || raw.starts_with('\\') || raw.starts_with("/\\")
}

/// `link` is `base` or below it. The boundary is checked explicitly, as
/// `MailRelay::check_origin` does: a bare `starts_with` would also accept
/// `https://invest.evinvest.ltd.attacker.example`.
fn is_under(base: &str, link: &str) -> bool {
	if link.chars().any(|c| c.is_whitespace() || c.is_control()) {
		return false;
	}
	link.strip_prefix(base)
		.is_some_and(|rest| rest.is_empty() || (rest.starts_with(['/', '?', '#']) && !rest.starts_with("//")))
}

fn join(base: &str, link: &str) -> String {
	if link.is_empty() {
		base.to_owned()
	} else {
		format!("{base}/{}", link.trim_start_matches('/'))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(raw: &[&str], production: bool) -> color_eyre::Result<NoticeLinkBases> {
		NoticeLinkBases::parse(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "https://evinvest.ltd", production)
	}

	const CABINET: &str = "https://evinvest.ltd/cabinet";

	#[test]
	fn the_list_takes_scope_equals_base_and_is_empty_by_default() {
		assert!(parse(&[], true).unwrap().bases.is_empty());
		let bases = parse(&["invest=https://invest.evinvest.ltd/cabinet", " sa=https://sa.evinvest.ltd "], true).unwrap();
		assert_eq!(bases.base("invest"), Some("https://invest.evinvest.ltd/cabinet"));
		assert_eq!(bases.base("sa"), Some("https://sa.evinvest.ltd"));
		assert_eq!(bases.base("main"), None);
	}

	#[test]
	fn a_malformed_entry_refuses_the_boot() {
		for bad in [
			"invest",
			"=https://invest.evinvest.ltd/cabinet",
			"Invest=https://invest.evinvest.ltd/cabinet",
			"in-vest=https://invest.evinvest.ltd/cabinet",
			"main=https://evinvest.ltd/cabinet",
			"invest=invest.evinvest.ltd/cabinet",
			"invest=/cabinet",
			"invest=https://invest.evinvest.ltd/cabinet/",
			"invest=http://invest.evinvest.ltd/cabinet",
			"invest=https://invest.evinvest.ltd:8443/cabinet",
			"invest=https://evinvest.ltd.attacker.example/cabinet",
			"invest=https://elsewhere.example/cabinet",
			"invest=https://user@invest.evinvest.ltd/cabinet",
			"invest=https://invest.evinvest.ltd/cabinet?x=1",
			"invest=https://invest.evinvest.ltd/cabinet#x",
			"invest=https://INVEST.evinvest.ltd/cabinet",
			"invest=https://invest.evinvest.ltd/a/../cabinet",
			"invest=https://*.evinvest.ltd/cabinet",
			"invest=https://invest.evinvest.ltd/cab inet",
		] {
			assert!(parse(&[bad], true).is_err(), "{bad:?} must refuse the boot");
		}
		assert!(
			parse(&["invest=https://invest.evinvest.ltd/cabinet", "invest=https://evinvest.ltd/x"], true).is_err(),
			"a scope named twice"
		);
	}

	#[test]
	fn outside_production_loopback_passes_and_a_foreign_host_still_does_not() {
		assert!(parse(&["invest=http://localhost:3001/cabinet"], false).is_ok());
		assert!(parse(&["invest=https://elsewhere.example/cabinet"], false).is_err());
		assert!(parse(&["invest=ftp://invest.evinvest.ltd/cabinet"], false).is_err());
	}

	#[test]
	fn an_emitter_names_a_path_and_never_a_host() {
		for ok in ["", "/wallet", "/wallet/action/payment/0b7c", "funds/quy-nhon", "/a?next=https://x", "/a#b"] {
			assert!(relative_link(ok).is_ok(), "{ok:?}");
		}
		for bad in [
			"https://invest.evinvest.ltd/cabinet/wallet",
			"http://attacker.example",
			"javascript:alert(1)",
			"//attacker.example",
			"/\\attacker.example",
			"\\\\attacker.example",
			"///attacker.example",
			"/wallet\nhttps://attacker.example",
			"/wallet https://attacker.example",
		] {
			assert!(relative_link(bad).is_err(), "{bad:?}");
		}
	}

	#[test]
	fn a_scope_with_a_base_stores_the_absolute_link_and_any_other_keeps_it_relative() {
		let bases = parse(&["invest=https://invest.evinvest.ltd/cabinet"], true).unwrap();
		assert_eq!(
			bases.stored_link("invest", "/wallet/action/payment/1").unwrap(),
			"https://invest.evinvest.ltd/cabinet/wallet/action/payment/1"
		);
		assert_eq!(bases.stored_link("invest", "").unwrap(), "https://invest.evinvest.ltd/cabinet");
		assert_eq!(bases.stored_link("", "/wallet").unwrap(), "/wallet");
		assert_eq!(bases.stored_link("sa", "/wallet").unwrap(), "/wallet", "no base: CABINET_URL decides at render");
		assert_eq!(bases.stored_link("main", "/wallet").unwrap(), "/wallet");
		for bad in ["Invest", "in-vest", "invest:x", "https://x"] {
			assert_eq!(bases.stored_link(bad, "/wallet").unwrap_err().code(), tonic::Code::InvalidArgument, "{bad:?}");
		}
		let long = format!("/{}", "a".repeat(500));
		assert_eq!(bases.stored_link("invest", &long).unwrap_err().code(), tonic::Code::InvalidArgument, "the column holds 512");
	}

	#[test]
	fn the_mail_passes_a_configured_base_and_joins_everything_else_onto_the_cabinet() {
		let bases = parse(&["invest=https://invest.evinvest.ltd/cabinet"], true).unwrap();
		let invest = "https://invest.evinvest.ltd/cabinet/wallet/action/payment/1";
		assert_eq!(bases.mail_target(CABINET, invest), invest);
		assert_eq!(bases.mail_target(CABINET, "/wallet"), "https://evinvest.ltd/cabinet/wallet");
		assert_eq!(bases.mail_target(&format!("{CABINET}/"), ""), CABINET);
		assert_eq!(bases.mail_target(CABINET, "https://evinvest.ltd/cabinet/x"), "https://evinvest.ltd/cabinet/x");
		for foreign in [
			"https://attacker.example/cabinet",
			"https://invest.evinvest.ltd/cabinetx",
			"https://invest.evinvest.ltd/cabinet.attacker.example/x",
			"https://invest.evinvest.ltd/cabinet//attacker.example",
			"https://invest.evinvest.ltd/cabinet/x\nhttps://attacker.example",
			"//attacker.example",
		] {
			assert_eq!(bases.mail_target(CABINET, foreign), CABINET, "{foreign:?}");
		}
	}

	#[test]
	fn a_base_removed_from_the_configuration_sends_its_old_links_to_the_cabinet() {
		let stored = parse(&["invest=https://invest.evinvest.ltd/cabinet"], true).unwrap().stored_link("invest", "/wallet").unwrap();
		assert_eq!(NoticeLinkBases::default().mail_target(CABINET, &stored), CABINET);
	}
}
