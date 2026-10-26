//! Second-factor material at rest: AES-256-GCM under one key this plane holds, each blob
//! bound to the row it was written for.
//!
//! A TOTP secret has to be read back to be checked, so it cannot be a digest like every
//! other credential here. The binding (factor, account, kind) is the AEAD's associated
//! data: a blob copied onto another row, another account or another kind does not open.

use color_eyre::eyre::{Context, ensure};
use domain::users::UserId;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use uuid::Uuid;

use super::FactorKind;

/// The envelope's first byte. A second key or cipher is a new version beside this one.
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"concierge.second_factor.v1";

pub struct SealKey(LessSafeKey);

impl SealKey {
	/// `SECOND_FACTOR_SEAL_KEY_FILE`: 32 random bytes, standard base64, alone in the file.
	pub fn from_file(path: &str) -> color_eyre::Result<Self> {
		use base64::{Engine, engine::general_purpose::STANDARD};
		let raw = std::fs::read_to_string(path).with_context(|| format!("SECOND_FACTOR_SEAL_KEY_FILE {path:?} is not readable"))?;
		let bytes = STANDARD.decode(raw.trim()).context("SECOND_FACTOR_SEAL_KEY_FILE does not hold standard base64")?;
		ensure!(bytes.len() == 32, "SECOND_FACTOR_SEAL_KEY_FILE must hold 32 bytes, it holds {}", bytes.len());
		Ok(Self(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &bytes).expect("32 bytes is an AES-256 key"))))
	}

	pub(crate) fn seal(&self, binding: &Binding, plaintext: &[u8]) -> Vec<u8> {
		let mut nonce = [0u8; NONCE_LEN];
		getrandom::fill(&mut nonce).expect("CSPRNG unavailable");
		let mut sealed = plaintext.to_vec();
		self.0
			.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(binding.aad()), &mut sealed)
			.expect("AES-GCM seals any length this plane writes");
		[&[VERSION][..], &nonce, &sealed].concat()
	}

	/// `None` for a blob that is not this key's for this row.
	pub(crate) fn open(&self, binding: &Binding, sealed: &[u8]) -> Option<Vec<u8>> {
		let (&version, rest) = sealed.split_first()?;
		if version != VERSION || rest.len() < NONCE_LEN {
			return None;
		}
		let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
		let mut buffer = ciphertext.to_vec();
		let plain = self.0.open_in_place(Nonce::try_assume_unique_for_key(nonce).ok()?, Aad::from(binding.aad()), &mut buffer).ok()?;
		Some(plain.to_vec())
	}
}

/// The row a blob belongs to.
pub(crate) struct Binding {
	pub factor: Uuid,
	pub user: UserId,
	pub kind: FactorKind,
}

impl Binding {
	fn aad(&self) -> Vec<u8> {
		let kind: &'static str = self.kind.into();
		[DOMAIN, self.factor.as_bytes(), self.user.raw().as_bytes(), kind.as_bytes()].concat()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn key() -> SealKey {
		SealKey(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[7u8; 32]).unwrap()))
	}

	fn binding(factor: Uuid, user: Uuid) -> Binding {
		Binding {
			factor,
			user: UserId::from_raw(user),
			kind: FactorKind::Totp,
		}
	}

	#[test]
	fn a_blob_opens_only_for_its_own_row() {
		let (factor, user) = (Uuid::new_v4(), Uuid::new_v4());
		let sealed = key().seal(&binding(factor, user), b"secret");
		assert_eq!(key().open(&binding(factor, user), &sealed).as_deref(), Some(&b"secret"[..]));
		assert!(key().open(&binding(Uuid::new_v4(), user), &sealed).is_none(), "another factor");
		assert!(key().open(&binding(factor, Uuid::new_v4()), &sealed).is_none(), "another account");
		let mut flipped = sealed.clone();
		*flipped.last_mut().unwrap() ^= 1;
		assert!(key().open(&binding(factor, user), &flipped).is_none(), "tampered");
		let other = SealKey(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[8u8; 32]).unwrap()));
		assert!(other.open(&binding(factor, user), &sealed).is_none(), "another key");
	}
}
