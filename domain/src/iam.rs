//! `iam` bounded context — what a user holds inside a tenant's namespace.
//!
//! A tenant (`sa`) owns one namespace and publishes its [`Catalog`]: the permissions and
//! aliases it defines. A grant names a [`Target`] inside a tenant namespace — an alias, a
//! permission or a `*` pattern — and is stored as named, so redefining an alias reaches
//! every holder. What a holder may do is resolved here against the current catalog;
//! clients only ever see the concrete result.
//!
//! Seats never live in a tenant namespace and are never granted: the namespaces below are
//! not a tenant's to claim, so no grant can reach a seat's permissions. A tenant's own
//! catalog may let the holders of an alias grant others (`Catalog::delegations`); nothing
//! else grants inside it but a seat holding [`Iam::Grant`], and nobody grants to themselves.

use std::collections::BTreeSet;

pub use concierge_iam::Catalog;
use concierge_iam::{ADMIN_ALIAS, EVERYONE_ALIAS, Pattern};

use crate::{
	authz::{Iam, Role},
	error::DomainError,
};

pub const RESERVED_NAMESPACES: [&str; 4] = ["iam", "concierge", "bank", "seat"];

/// What a grant names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
	/// `<namespace>:<name>`, defined by the tenant's catalog.
	Alias(String),
	/// A permission, or permissions by `*` segments.
	Pattern(Pattern),
}

impl Target {
	pub fn parse(raw: &str) -> Result<Self, DomainError> {
		let pattern = Pattern::parse(raw).map_err(DomainError::Validation)?;
		if RESERVED_NAMESPACES.contains(&pattern.namespace()) {
			return Err(DomainError::Validation(format!("`{}:*` is not grantable: only a tenant's namespace is", pattern.namespace())));
		}
		Ok(match raw.split(':').count() == 2 && !raw.contains('*') {
			true => Self::Alias(raw.to_owned()),
			false => Self::Pattern(pattern),
		})
	}

	pub fn as_str(&self) -> &str {
		match self {
			Self::Alias(name) => name,
			Self::Pattern(pattern) => pattern.as_str(),
		}
	}

	pub fn namespace(&self) -> &str {
		self.as_str().split(':').next().expect("parse refuses an empty target")
	}

	/// The permissions of `catalog` this target grants. None: the target is orphaned.
	pub fn grants<'c>(&self, catalog: &'c Catalog) -> BTreeSet<&'c str> {
		match self {
			Self::Alias(name) => catalog.aliases.get(name).into_iter().flatten().map(String::as_str).collect(),
			Self::Pattern(pattern) => catalog.permissions.iter().filter(|p| pattern.matches(p)).map(String::as_str).collect(),
		}
	}
}

/// Everything `seat` and `targets` let a user do inside `catalog`'s namespace, plus the
/// `everyone` alias when they are a `member` of its scope. A seat that may grant there holds
/// all of it only in a tenant that says so (`tenants.granting_seats_hold_all`); elsewhere it
/// holds what someone else granted it.
pub fn resolve<'c>(seat: Role, granting_seats_hold_all: bool, member: bool, targets: &[Target], catalog: &'c Catalog) -> BTreeSet<&'c str> {
	if granting_seats_hold_all && seat.may(Iam::Grant) {
		return catalog.permissions.iter().map(String::as_str).collect();
	}
	let everyone = catalog
		.aliases
		.iter()
		.filter(|(name, _)| member && name.split_once(':').is_some_and(|(_, name)| name == EVERYONE_ALIAS))
		.flat_map(|(_, members)| members.iter().map(String::as_str));
	targets.iter().flat_map(|t| t.grants(catalog)).chain(everyone).collect()
}

/// The aliases a holder of `targets` may grant and revoke in `catalog`'s namespace.
///
/// Never `<namespace>:admin`, whatever the catalog says: that alias is the scope's
/// approval roster, and a holder able to revoke it could empty the roster of everyone but
/// themselves and pass the scope's quorum alone. `Catalog::check` refuses such a
/// delegation at publication; this is the same rule for a catalog stored before it.
pub fn delegable<'c>(targets: &[Target], catalog: &'c Catalog) -> BTreeSet<&'c str> {
	targets
		.iter()
		.filter_map(|t| catalog.delegations.get(t.as_str()))
		.flatten()
		.map(String::as_str)
		.filter(|alias| alias.split_once(':').is_none_or(|(_, name)| name != ADMIN_ALIAS))
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn catalog() -> Catalog {
		serde_json::from_value(serde_json::json!({
			"version": 1,
			"permissions": ["sa:work:leads:read", "sa:work:leads:edit", "sa:admin:sources:manage"],
			"aliases": {
				"sa:operator": ["sa:work:leads:read", "sa:work:leads:edit"],
				"sa:admin": ["sa:admin:sources:manage"],
			},
			"delegations": { "sa:admin": ["sa:operator"] },
		}))
		.unwrap()
	}

	fn targets(raw: &[&str]) -> Vec<Target> {
		raw.iter().map(|t| Target::parse(t).unwrap()).collect()
	}

	fn check(seat: Role, raw: &[&str], expected: &[&str]) {
		let catalog = catalog();
		assert_eq!(resolve(seat, true, false, &targets(raw), &catalog), expected.iter().copied().collect(), "{seat:?} {raw:?}");
	}

	#[test]
	fn resolution() {
		check(Role::Investor, &[], &[]);
		check(Role::Investor, &["sa:operator"], &["sa:work:leads:edit", "sa:work:leads:read"]);
		check(Role::Investor, &["sa:work:*"], &["sa:work:leads:edit", "sa:work:leads:read"]);
		check(
			Role::Investor,
			&["sa:admin:sources:manage", "sa:work:leads:read"],
			&["sa:admin:sources:manage", "sa:work:leads:read"],
		);
		check(Role::Investor, &["sa:gone", "sa:work:gone:*"], &[]);
		check(Role::Operator, &[], &[]);
		check(Role::Admin, &[], &["sa:admin:sources:manage", "sa:work:leads:edit", "sa:work:leads:read"]);
		assert!(resolve(Role::Admin, false, false, &[], &catalog()).is_empty(), "a tenant that does not trust seats");
	}

	#[test]
	fn a_member_holds_the_everyone_alias() {
		let mut catalog = catalog();
		catalog.aliases.insert("sa:everyone".into(), ["sa:work:leads:read".into()].into());
		let operator = targets(&["sa:operator"]);
		assert_eq!(resolve(Role::Investor, false, true, &[], &catalog), ["sa:work:leads:read"].into());
		assert!(resolve(Role::Investor, false, false, &[], &catalog).is_empty(), "not a member");
		assert_eq!(resolve(Role::Investor, false, true, &operator, &catalog), ["sa:work:leads:edit", "sa:work:leads:read"].into());
		catalog.aliases.remove("sa:everyone");
		assert!(resolve(Role::Investor, false, true, &[], &catalog).is_empty(), "republished without it");
	}

	#[test]
	fn delegation() {
		let catalog = catalog();
		assert_eq!(delegable(&targets(&["sa:admin"]), &catalog), ["sa:operator"].into());
		assert!(
			delegable(&targets(&["sa:operator", "sa:admin:*", "sa:*"]), &catalog).is_empty(),
			"only the alias itself delegates"
		);
	}

	#[test]
	fn a_stored_catalog_never_delegates_the_admin_alias() {
		let stored: Catalog = serde_json::from_value(serde_json::json!({
			"version": 1,
			"permissions": ["sa:work:leads:read"],
			"aliases": { "sa:operator": ["sa:work:leads:read"], "sa:lead": ["sa:work:leads:read"], "sa:admin": ["sa:work:leads:read"] },
			"delegations": { "sa:admin": ["sa:admin", "sa:operator"], "sa:lead": ["sa:admin"] },
		}))
		.unwrap();
		assert_eq!(delegable(&targets(&["sa:admin"]), &stored), ["sa:operator"].into());
		assert!(delegable(&targets(&["sa:lead"]), &stored).is_empty());
	}

	#[test]
	fn seats_and_their_namespaces_are_not_grantable() {
		for raw in [
			"iam:tenants:grant",
			"iam:*",
			"concierge:*",
			"concierge:role:grant",
			"bank:*",
			"bank:treasury:read",
			"seat:owner",
			"owner",
			"admin",
			"*",
			"",
		] {
			assert!(Target::parse(raw).is_err(), "{raw:?}");
		}
		assert!(Target::parse(&format!("sa:{}", "a".repeat(concierge_iam::MAX_NAME_CHARS))).is_err());
	}
}
