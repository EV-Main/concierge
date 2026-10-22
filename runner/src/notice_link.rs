//! Where a notice's link points (banking#580).
//!
//! An emitter names a cabinet-RELATIVE path, never a host. A notice about a scope's
//! business links to that scope's own cabinet, so the emitter may also name the scope
//! (`EmitRequest.link_scope`), and this plane looks its base up in `NOTICE_LINK_BASES`.
//! The emit stores the finished absolute link, because the inbox row is read by the
//! frontends as it is stored and no column holds the scope. Without a base the link stays
//! relative and the mail joins it onto `CABINET_URL`, as before.
//!
//! The property kept: neither a mail nor an inbox read links outside `CABINET_URL` or a
//! configured base. The host comes only from this plane's configuration, and a stored
//! absolute link is checked again against the configuration in force whenever it leaves
//! this plane — rows outlive both the emit rule and the configuration.
//!
//! `Result<_, Status>` is tonic's handler error, so the large-err lint does not apply.
#![allow(clippy::result_large_err)]

use color_eyre::eyre::{Context, bail, ensure};
use domain::scopes::{ROOT, is_scope_name};
use tonic::Status;
use webauthn_rs::prelude::Url;

/// The column CHECK `notifications_link_len` (migration 0008), counted in characters.
const LINK_MAX_CHARS: usize = 512;

/// `CABINET_URL` and `NOTICE_LINK_BASES`, parsed: the cabinets a notice may link into.
#[derive(Clone, Debug)]
pub struct NoticeLinkBases {
	/// `CABINET_URL` without a trailing slash: a relative link's cabinet.
	cabinet: String,
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
	pub fn parse(raw: &[String], cabinet_url: &str, public_origin: &str, production: bool) -> color_eyre::Result<Self> {
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
		Ok(Self {
			bases,
			..Self::cabinet_only(cabinet_url)
		})
	}

	/// No scope bases: every link is under `cabinet_url`.
	pub fn cabinet_only(cabinet_url: &str) -> Self {
		Self {
			cabinet: cabinet_url.trim_end_matches('/').to_owned(),
			bases: Vec::new(),
		}
	}

	pub fn base(&self, scope: &str) -> Option<&str> {
		self.bases.iter().find(|(s, _)| s == scope).map(|(_, base)| base.as_str())
	}

	/// The link an emit stores. `link` has passed [`cabinet_path`] already.
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
	/// `CABINET_URL` or a base configured NOW, checked at a path boundary. Anything else
	/// that is absolute — its base was removed from the configuration since, or the row
	/// was never composed here — links to `CABINET_URL` itself: the old host is not
	/// trusted any longer, and the relative part cannot be recovered without the old
	/// base. A cabinet path is joined onto `CABINET_URL`. A row that is neither — or that
	/// carries any byte outside printable ASCII — was written before emitters were held to
	/// [`cabinet_path`], and also links to `CABINET_URL` itself.
	pub fn mail_target(&self, stored: &str) -> String {
		match self.kind(stored) {
			Stored::Empty => self.cabinet.clone(),
			Stored::Path => join(&self.cabinet, stored),
			Stored::Trusted => stored.to_owned(),
			Stored::Untrusted => {
				tracing::warn!(link = stored, "a stored notice link is under no configured cabinet; the mail links to CABINET_URL");
				self.cabinet.clone()
			}
		}
	}

	/// The link an inbox read returns: the same rule as [`Self::mail_target`], except that
	/// a link that fails it is dropped rather than replaced — the reader keeps the notice
	/// and loses only the click. The cabinets put their own origin in front of a path and
	/// use an absolute link as given, so what leaves here is empty, a cabinet path, or a
	/// URL under a cabinet configured now.
	pub fn inbox_link(&self, stored: &str) -> String {
		match self.kind(stored) {
			Stored::Empty => String::new(),
			Stored::Path | Stored::Trusted => stored.to_owned(),
			Stored::Untrusted => {
				tracing::warn!(link = stored, "a stored notice link is under no configured cabinet; the inbox returns no link");
				String::new()
			}
		}
	}

	fn kind(&self, stored: &str) -> Stored {
		if stored.is_empty() {
			return Stored::Empty;
		}
		if !stored.bytes().all(|b| b.is_ascii_graphic()) {
			return Stored::Untrusted;
		}
		if cabinet_path(stored).is_ok() {
			return Stored::Path;
		}
		let trusted = std::iter::once(self.cabinet.as_str())
			.chain(self.bases.iter().map(|(_, base)| base.as_str()))
			.any(|base| is_under(base, stored));
		if trusted { Stored::Trusted } else { Stored::Untrusted }
	}
}

/// What a stored link is, judged against the configuration in force.
enum Stored {
	Empty,
	/// A cabinet path: relative to `CABINET_URL`.
	Path,
	/// Absolute, under `CABINET_URL` or a configured base.
	Trusted,
	/// Anything else: a row from before the emit rule, or a base removed since.
	Untrusted,
}

/// A CABINET-RELATIVE path, the only link an emitter may send: the host is this plane's
/// to choose (`CABINET_URL`, or a base by `link_scope`). One leading `/` and printable
/// ASCII only — `//host` is protocol-relative and `/\host` is what browsers make of it,
/// so both are refused, and so is a path without the `/` (`@host/x`), which a reader that
/// writes origin + link turns into another host. ASCII, because the mail's text part
/// prints the link bare on its own line: an invisible character (U+200B, U+202E) folds
/// to a space there and starts a second, foreign link on that line. The empty path means
/// the cabinet's front page. The money plane's fee notice link is held to the same rule.
pub fn cabinet_path(raw: &str) -> Result<String, Status> {
	if raw.is_empty() {
		return Ok(String::new());
	}
	if raw.len() > LINK_MAX_CHARS {
		return Err(Status::invalid_argument(format!("link must be at most {LINK_MAX_CHARS} bytes")));
	}
	if !raw.bytes().all(|b| b.is_ascii_graphic()) {
		return Err(Status::invalid_argument("link must not contain whitespace or non-printable characters"));
	}
	let mut chars = raw.chars();
	if chars.next() != Some('/') || matches!(chars.next(), Some('/' | '\\')) {
		return Err(Status::invalid_argument("link must be a cabinet-relative path starting with a single '/'"));
	}
	Ok(raw.to_owned())
}

/// `link` is `base` or below it. The boundary is checked explicitly, as
/// `MailRelay::check_origin` does: a bare `starts_with` would also accept
/// `https://invest.evinvest.ltd.attacker.example`.
fn is_under(base: &str, link: &str) -> bool {
	if !link.bytes().all(|b| b.is_ascii_graphic()) {
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
		NoticeLinkBases::parse(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>(), CABINET, "https://evinvest.ltd", production)
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
		for ok in ["", "/wallet", "/wallet/action/payment/0b7c", "/invest/quy-nhon", "/a?next=https://x", "/a#b"] {
			assert!(cabinet_path(ok).is_ok(), "{ok:?}");
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
			"/x\u{200B}https://phish.example/login",
			"/x\u{202E}",
			"/x\u{FEFF}",
			"@phish.example/x",
			"funds/quy-nhon",
		] {
			assert!(cabinet_path(bad).is_err(), "{bad:?}");
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
		assert_eq!(bases.mail_target(invest), invest);
		assert_eq!(bases.mail_target("/wallet"), "https://evinvest.ltd/cabinet/wallet");
		assert_eq!(NoticeLinkBases::cabinet_only(&format!("{CABINET}/")).mail_target(""), CABINET);
		assert_eq!(bases.mail_target("https://evinvest.ltd/cabinet/x"), "https://evinvest.ltd/cabinet/x");
		for foreign in [
			"https://attacker.example/cabinet",
			"https://invest.evinvest.ltd/cabinetx",
			"https://invest.evinvest.ltd/cabinet.attacker.example/x",
			"https://invest.evinvest.ltd/cabinet//attacker.example",
			"https://invest.evinvest.ltd/cabinet/x\nhttps://attacker.example",
			"https://invest.evinvest.ltd/cabinet/x\u{200B}https://attacker.example",
			"//attacker.example",
			"/x\nhttps://attacker.example",
			"/x\u{200B}https://phish.example/login",
			"@phish.example/x",
		] {
			assert_eq!(bases.mail_target(foreign), CABINET, "{foreign:?}");
			assert_eq!(bases.inbox_link(foreign), "", "{foreign:?}");
		}
	}

	#[test]
	fn a_base_removed_from_the_configuration_sends_its_old_links_to_the_cabinet() {
		let stored = parse(&["invest=https://invest.evinvest.ltd/cabinet"], true).unwrap().stored_link("invest", "/wallet").unwrap();
		let retired = NoticeLinkBases::cabinet_only(CABINET);
		assert_eq!(retired.mail_target(&stored), CABINET);
		assert_eq!(retired.inbox_link(&stored), "");
	}

	/// Rows written before the emit rule held only a length check, so an inbox read is the
	/// last place a hostile one can be stopped before a cabinet renders it as a link.
	#[test]
	fn the_inbox_returns_a_path_or_a_configured_cabinet_and_drops_anything_else() {
		let bases = parse(&["invest=https://invest.evinvest.ltd/cabinet"], true).unwrap();
		for kept in [
			"",
			"/wallet",
			"/wallet/action/payment/1?x=1",
			"https://invest.evinvest.ltd/cabinet/wallet",
			"https://evinvest.ltd/cabinet/x",
		] {
			assert_eq!(bases.inbox_link(kept), kept, "{kept:?}");
		}
		for dropped in [
			"https://phish.example/login",
			"javascript:alert(1)",
			"data:text/html,x",
			"funds/quy-nhon",
			"@phish.example/x",
			"/x\u{200B}y",
			"/x y",
			"https://sa.evinvest.ltd/cabinet/x",
		] {
			assert_eq!(bases.inbox_link(dropped), "", "{dropped:?}");
		}
	}
}
