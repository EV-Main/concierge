//! Step-up proofs: a short token saying "this account just proved a second factor for THIS
//! operation".
//!
//! Minted by the web surface's `/auth/stepup/verify` after the account answered one of its
//! second factors in a ceremony bound, on the server, to the hash of one operation. The
//! money plane's BFF checks it with [`verify_stepup_proof`] against the same JWKS it reads
//! access tokens with, and accepts it only for an `intent_hash` it stored itself.
//!
//! The proof names no factor: it says how much assurance the answer gave ([`Aal`]), never
//! which kind of factor gave it, so a kind added to this plane changes nothing a verifier
//! does. A verifier asks for a minimum level and gets that or more.
//!
//! It is deliberately NOT a [`Claims`](crate::Claims) token: `typ` is `"stepup"` (not a
//! [`TokenType`](crate::TokenType), so every access/service verifier refuses it at parse)
//! and `aud` is the BFF's own, which no access policy lists. The reverse holds too: an
//! access token has neither `typ=stepup` nor an `intent_hash`, so it cannot pass here.
//!
//! Replay protection is the consumer's: the proof carries a `jti` and lives at most
//! [`MAX_TTL_SECS`]; the verifier of record must remember the `jti` until `exp` in a
//! store shared by all its replicas and refuse a second presentation. This crate cannot
//! do it for them.

use jsonwebtoken::{Algorithm, Validation, decode, decode_header, get_current_timestamp};
use serde::{Deserialize, Serialize};

use crate::jwks::JwksCache;

/// The `aud` of every proof: the money plane's BFF, and nobody else.
pub const AUDIENCE: &str = "banking-bff";
/// The `typ` of every proof.
pub const TYP: &str = "stepup";
/// The longest a proof may live, and the longest a verifier will believe one lives.
pub const MAX_TTL_SECS: u64 = 120;
/// Clock skew tolerated between this plane and the verifier. Short on purpose: the
/// default of a minute would be half the proof's whole life.
const LEEWAY_SECS: u64 = 5;

/// The assurance an answer gave, numbered as NIST SP 800-63B numbers authenticator
/// assurance levels. Ordered and numeric on the wire, so a level added later passes every
/// verifier that asks for less.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Aal(u8);

impl Aal {
	/// The account's sign-in and, on top of it, a second factor it enrolled.
	pub const SECOND_FACTOR: Self = Self(2);

	pub fn level(self) -> u8 {
		self.0
	}

	/// The level a caller names on the wire; `None` for one no proof can carry.
	pub fn named(level: u8) -> Option<Self> {
		(level >= Self::SECOND_FACTOR.0).then_some(Self(level))
	}
}

/// The claims of a proof. Unknown claims are tolerated on read so a later field does not
/// break an older verifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StepupClaims {
	/// The account, as in an access token's `sub`.
	pub sub: String,
	pub iss: String,
	pub aud: String,
	pub exp: u64,
	pub iat: u64,
	pub typ: String,
	/// The operation, as 64 lowercase hex characters (32 bytes) — the bank's own hash of
	/// what it stored.
	pub intent_hash: String,
	pub aal: Aal,
	/// The page the person confirmed on, as the browser reported it (`Origin`).
	pub origin: String,
	/// Unique per proof; the consumer spends it once.
	pub jti: String,
}

/// A minted proof and the facts the caller answers with.
#[derive(Clone, Debug)]
pub struct StepupProof {
	pub token: String,
	pub jti: String,
	pub exp: u64,
}

/// What the verifier of record already knows and the proof must match.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
	pub intent_hash: &'a [u8; 32],
	pub sub: &'a str,
	pub origin: &'a str,
	/// The least assurance the bank accepts for THIS operation. A policy of the verifier,
	/// not of the proof.
	pub min_aal: Aal,
}

/// Why a proof was not accepted. Callers answer all of these alike to a client.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StepupError {
	/// Malformed, badly signed, expired, wrong issuer/audience/`typ`, or lives too long.
	#[error("invalid or expired step-up proof")]
	Invalid,
	/// The signing key is not in the cache; refresh the JWKS once and retry.
	#[error("unknown signing key: {0}")]
	UnknownKid(String),
	/// A genuine proof, but of another account, operation or page, or of less assurance
	/// than the operation asks.
	#[error("step-up proof is for another {0}")]
	Mismatch(&'static str),
}

pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(64);
	for b in bytes {
		out.push(DIGITS[(b >> 4) as usize] as char);
		out.push(DIGITS[(b & 0x0f) as usize] as char);
	}
	out
}

/// Parse the 64-hex-character form of an intent hash (lowercase only, so one operation
/// has one spelling).
pub fn parse_intent_hash(raw: &str) -> Option<[u8; 32]> {
	if raw.len() != 64 {
		return None;
	}
	let mut out = [0u8; 32];
	for (i, pair) in raw.as_bytes().chunks(2).enumerate() {
		let digit = |c: u8| match c {
			b'0'..=b'9' => Some(c - b'0'),
			b'a'..=b'f' => Some(c - b'a' + 10),
			_ => None,
		};
		out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
	}
	Some(out)
}

/// Verify a proof against the cached JWKS and the operation the verifier holds.
///
/// Checks the signature (EdDSA, pinned), `iss`, `aud`, `exp`, `typ`, that the proof does
/// not live longer than [`MAX_TTL_SECS`] nor reach past `now + MAX_TTL_SECS`, then that
/// `sub`, `intent_hash` and `origin` are exactly the expected ones and `aal` is at least
/// `min_aal`. A proof without `aal` is refused. On success the caller still owes the replay
/// check: spend `jti` (until `exp`) in a shared store and refuse the proof if it was spent.
pub fn verify_stepup_proof(token: &str, cache: &JwksCache, issuer: &str, expected: &Expected<'_>) -> Result<StepupClaims, StepupError> {
	let header = decode_header(token).map_err(|_| StepupError::Invalid)?;
	if header.alg != Algorithm::EdDSA {
		return Err(StepupError::Invalid);
	}
	let kid = header.kid.ok_or(StepupError::Invalid)?;
	let key = cache.get(&kid).ok_or(StepupError::UnknownKid(kid))?;

	let mut validation = Validation::new(Algorithm::EdDSA);
	validation.set_issuer(&[issuer]);
	validation.set_audience(&[AUDIENCE]);
	validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
	validation.leeway = LEEWAY_SECS;
	let claims = decode::<StepupClaims>(token, key, &validation).map_err(|_| StepupError::Invalid)?.claims;

	// A proof dated ahead of this verifier's clock, or ending later than a proof can live,
	// was not minted by this plane's signer however well it is signed.
	let now = get_current_timestamp();
	if claims.typ != TYP || claims.jti.is_empty() || claims.exp.saturating_sub(claims.iat) > MAX_TTL_SECS || claims.iat > now + LEEWAY_SECS || claims.exp > now + MAX_TTL_SECS + LEEWAY_SECS {
		return Err(StepupError::Invalid);
	}
	if claims.sub != expected.sub {
		return Err(StepupError::Mismatch("account"));
	}
	if claims.intent_hash != hex32(expected.intent_hash) {
		return Err(StepupError::Mismatch("operation"));
	}
	if claims.origin != expected.origin {
		return Err(StepupError::Mismatch("origin"));
	}
	if claims.aal < expected.min_aal {
		return Err(StepupError::Mismatch("assurance"));
	}
	Ok(claims)
}

#[cfg(test)]
mod tests {
	use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};

	use super::*;
	use crate::{
		claims::TokenType,
		config::{AuthConfig, SigningConfig},
		jwks::{VerifyPolicy, verify_token},
		signer::{Signer, load_jwks},
	};

	// The same throwaway Ed25519 keypair as the signer tests.
	const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKolOSMXwE+tafZkX+jkKYJbmJ066f4E12wAwTIkKps6\n-----END PRIVATE KEY-----\n";
	const TEST_JWK_X: &str = "Z6BCmq9-_wo9d7co5CDW84Wn0sAC3BA0XWK2AOstpV4";
	const ISSUER: &str = "https://auth.test";
	const ORIGIN: &str = "https://invest.evinvest.ltd";
	const SUB: &str = "00000000-0000-0000-0000-000000000001";
	const HASH: [u8; 32] = [7; 32];

	fn signing() -> SigningConfig {
		SigningConfig {
			signing_key_pem: TEST_PEM.into(),
			kid: "test-kid".into(),
			jwks_json: format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{TEST_JWK_X}","kid":"test-kid","alg":"EdDSA","use":"sig"}}]}}"#),
		}
	}

	fn config() -> AuthConfig {
		AuthConfig {
			issuer: ISSUER.into(),
			client_audience: "concierge".into(),
			service_audience: "concierge-services".into(),
			access_ttl_secs: 900,
			refresh_ttl_secs: 3600,
			max_session_secs: 7_776_000,
			idle_timeout_secs: 0,
			service_ttl_secs: 300,
			signing: Some(signing()),
			google: None,
			github: None,
		}
	}

	fn signer() -> Signer {
		Signer::try_new(&signing(), &config()).unwrap()
	}

	fn cache() -> JwksCache {
		load_jwks(&signing()).unwrap().0
	}

	fn expected() -> Expected<'static> {
		Expected {
			intent_hash: &HASH,
			sub: SUB,
			origin: ORIGIN,
			min_aal: Aal::SECOND_FACTOR,
		}
	}

	fn proof() -> String {
		signer().mint_stepup(SUB, &HASH, Aal::SECOND_FACTOR, ORIGIN, 120).unwrap().token
	}

	#[test]
	fn a_proof_verifies_for_exactly_its_operation() {
		let claims = verify_stepup_proof(&proof(), &cache(), ISSUER, &expected()).unwrap();
		assert_eq!((claims.sub.as_str(), claims.aal, claims.origin.as_str()), (SUB, Aal::SECOND_FACTOR, ORIGIN));
		assert_eq!(claims.intent_hash, hex32(&HASH));
		assert_eq!(claims.aud, AUDIENCE);
		assert!(claims.exp - claims.iat <= MAX_TTL_SECS);
		assert!(!claims.jti.is_empty());
	}

	#[test]
	fn another_operation_account_or_page_is_refused() {
		let token = proof();
		let other = [8u8; 32];
		let wrong_hash = Expected { intent_hash: &other, ..expected() };
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &wrong_hash).unwrap_err(), StepupError::Mismatch("operation"));
		let wrong_sub = Expected { sub: "someone-else", ..expected() };
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &wrong_sub).unwrap_err(), StepupError::Mismatch("account"));
		let wrong_origin = Expected {
			origin: "https://rogue.evinvest.ltd",
			..expected()
		};
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &wrong_origin).unwrap_err(), StepupError::Mismatch("origin"));
		assert_eq!(verify_stepup_proof(&token, &cache(), "https://other.issuer", &expected()).unwrap_err(), StepupError::Invalid);
	}

	#[test]
	fn a_proof_of_less_assurance_than_the_operation_asks_is_refused_and_more_passes() {
		let higher = Aal::named(3).unwrap();
		let wants_more = Expected { min_aal: higher, ..expected() };
		assert_eq!(verify_stepup_proof(&proof(), &cache(), ISSUER, &wants_more).unwrap_err(), StepupError::Mismatch("assurance"));
		let stronger = signer().mint_stepup(SUB, &HASH, higher, ORIGIN, 120).unwrap().token;
		assert_eq!(verify_stepup_proof(&stronger, &cache(), ISSUER, &expected()).unwrap().aal, higher);
		assert_eq!(Aal::named(1), None, "no proof is of a single factor");
	}

	#[test]
	fn a_proof_without_an_assurance_level_is_refused() {
		let now = get_current_timestamp();
		let claims = serde_json::json!({
			"sub": SUB, "iss": ISSUER, "aud": AUDIENCE, "exp": now + 100, "iat": now, "typ": TYP,
			"intent_hash": hex32(&HASH), "origin": ORIGIN, "jti": "j",
		});
		let mut header = Header::new(Algorithm::EdDSA);
		header.kid = Some("test-kid".into());
		let token = encode(&header, &claims, &EncodingKey::from_ed_pem(TEST_PEM.as_bytes()).unwrap()).unwrap();
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::Invalid);
	}

	#[test]
	fn a_proof_dated_ahead_of_the_clock_is_refused() {
		let now = get_current_timestamp();
		for (iat, ttl) in [(now + 600, 60), (now + 3600, 120), (now + LEEWAY_SECS + 30, 1)] {
			let (token, _) = signer_token_at(iat, ttl);
			assert_eq!(
				verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(),
				StepupError::Invalid,
				"iat {} ahead",
				iat - now
			);
		}
		let (within_skew, _) = signer_token_at(now + 2, 100);
		assert!(verify_stepup_proof(&within_skew, &cache(), ISSUER, &expected()).is_ok(), "a little skew is tolerated");
	}

	#[test]
	fn an_expired_proof_is_refused() {
		let (token, _) = signer_token_at(get_current_timestamp() - 300, 120);
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::Invalid);
	}

	#[test]
	fn a_proof_that_lives_too_long_is_refused() {
		let (token, _) = signer_token_at(get_current_timestamp(), 3600);
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::Invalid);
	}

	/// Mint with a `ttl` the public method would clamp, to show the verifier does not
	/// trust the minter to have clamped it.
	fn signer_token_at(now: u64, ttl: u64) -> (String, u64) {
		let claims = StepupClaims {
			sub: SUB.into(),
			iss: ISSUER.into(),
			aud: AUDIENCE.into(),
			exp: now + ttl,
			iat: now,
			typ: TYP.into(),
			intent_hash: hex32(&HASH),
			aal: Aal::SECOND_FACTOR,
			origin: ORIGIN.into(),
			jti: "j".into(),
		};
		let mut header = Header::new(Algorithm::EdDSA);
		header.kid = Some("test-kid".into());
		(encode(&header, &claims, &EncodingKey::from_ed_pem(TEST_PEM.as_bytes()).unwrap()).unwrap(), claims.exp)
	}

	#[test]
	fn the_minter_clamps_the_lifetime() {
		let minted = signer().mint_stepup(SUB, &HASH, Aal::SECOND_FACTOR, ORIGIN, 3600).unwrap();
		assert!(minted.exp <= get_current_timestamp() + MAX_TTL_SECS);
	}

	#[test]
	fn a_proof_is_not_an_access_token_and_an_access_token_is_not_a_proof() {
		let access_policy = VerifyPolicy {
			issuer: ISSUER.into(),
			audiences: vec!["concierge".into(), AUDIENCE.into()],
			allowed_types: vec![TokenType::Access, TokenType::Service],
		};
		// Even with the proof's audience listed, `typ=stepup` is not a token type.
		assert!(verify_token(&proof(), &cache(), &access_policy).is_err());
		let (access, _) = signer().mint_access(SUB, 0, None).unwrap();
		assert_eq!(verify_stepup_proof(&access, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::Invalid);
	}

	#[test]
	fn a_downgraded_algorithm_is_refused() {
		let claims = StepupClaims {
			sub: SUB.into(),
			iss: ISSUER.into(),
			aud: AUDIENCE.into(),
			exp: get_current_timestamp() + 100,
			iat: get_current_timestamp(),
			typ: TYP.into(),
			intent_hash: hex32(&HASH),
			aal: Aal::SECOND_FACTOR,
			origin: ORIGIN.into(),
			jti: "j".into(),
		};
		let mut header = Header::new(Algorithm::HS256);
		header.kid = Some("test-kid".into());
		let token = encode(&header, &claims, &EncodingKey::from_secret(b"attacker")).unwrap();
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::Invalid);
	}

	#[test]
	fn an_unknown_key_asks_for_a_refresh() {
		let mut header = Header::new(Algorithm::EdDSA);
		header.kid = Some("rotated".into());
		let claims = serde_json::json!({ "sub": SUB });
		let token = encode(&header, &claims, &EncodingKey::from_ed_pem(TEST_PEM.as_bytes()).unwrap()).unwrap();
		assert_eq!(verify_stepup_proof(&token, &cache(), ISSUER, &expected()).unwrap_err(), StepupError::UnknownKid("rotated".into()));
	}

	#[test]
	fn an_intent_hash_has_one_spelling() {
		let letters = [0xab; 32];
		let hex = hex32(&letters);
		assert_eq!(parse_intent_hash(&hex), Some(letters));
		assert_eq!(parse_intent_hash(&hex.to_uppercase()), None);
		assert_eq!(parse_intent_hash(&hex[..62]), None);
		assert_eq!(parse_intent_hash(&format!("{}zz", &hex[..62])), None);
		assert_eq!(parse_intent_hash(""), None);
	}

	#[test]
	fn the_wire_claim_set_is_pinned() {
		let claims = serde_json::to_value(verify_stepup_proof(&proof(), &cache(), ISSUER, &expected()).unwrap()).unwrap();
		let mut keys: Vec<_> = claims.as_object().unwrap().keys().cloned().collect();
		keys.sort();
		assert_eq!(keys, ["aal", "aud", "exp", "iat", "intent_hash", "iss", "jti", "origin", "sub", "typ"]);
		assert_eq!(claims["typ"], "stepup");
		assert_eq!(claims["aal"], 2, "a number, so a higher level passes a verifier that asks for less");
	}
}
