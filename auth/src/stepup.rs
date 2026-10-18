//! Step-up proofs: a short token saying "this account just confirmed THIS operation".
//!
//! Minted by the web surface's `/auth/stepup/verify` after a passkey assertion or a mailed
//! code that was bound, on the server, to the hash of one operation. The money plane's
//! BFF checks it with [`verify_stepup_proof`] against the same JWKS it reads access
//! tokens with, and accepts it only for an `intent_hash` it stored itself.
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

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
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

/// How the account proved the operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepupMethod {
	Passkey,
	EmailCode,
}

impl StepupMethod {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Passkey => "passkey",
			Self::EmailCode => "email_code",
		}
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
	pub method: StepupMethod,
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
	/// A genuine proof, but of another account, operation or page.
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
/// not live longer than [`MAX_TTL_SECS`], then that `sub`, `intent_hash` and `origin`
/// are exactly the expected ones. On success the caller still owes the replay check:
/// spend `jti` (until `exp`) in a shared store and refuse the proof if it was spent.
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

	if claims.typ != TYP || claims.jti.is_empty() || claims.exp.saturating_sub(claims.iat) > MAX_TTL_SECS {
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
		}
	}

	fn proof() -> String {
		signer().mint_stepup(SUB, &HASH, StepupMethod::Passkey, ORIGIN, 120).unwrap().token
	}

	#[test]
	fn a_proof_verifies_for_exactly_its_operation() {
		let claims = verify_stepup_proof(&proof(), &cache(), ISSUER, &expected()).unwrap();
		assert_eq!((claims.sub.as_str(), claims.method, claims.origin.as_str()), (SUB, StepupMethod::Passkey, ORIGIN));
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
			method: StepupMethod::Passkey,
			origin: ORIGIN.into(),
			jti: "j".into(),
		};
		let mut header = Header::new(Algorithm::EdDSA);
		header.kid = Some("test-kid".into());
		(encode(&header, &claims, &EncodingKey::from_ed_pem(TEST_PEM.as_bytes()).unwrap()).unwrap(), claims.exp)
	}

	#[test]
	fn the_minter_clamps_the_lifetime() {
		let minted = signer().mint_stepup(SUB, &HASH, StepupMethod::EmailCode, ORIGIN, 3600).unwrap();
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
			method: StepupMethod::Passkey,
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
		assert_eq!(keys, ["aud", "exp", "iat", "intent_hash", "iss", "jti", "method", "origin", "sub", "typ"]);
		assert_eq!(claims["typ"], "stepup");
		assert_eq!(claims["method"], "passkey");
	}
}
