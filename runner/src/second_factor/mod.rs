//! Second factors: a way the account proves itself beyond its sign-in, enrolled here and
//! asked for before money leaves (`docs/STEPUP-PROOF.md`).
//!
//! A kind is one [`FactorKind`] variant and one [`Factor`] impl. What a kind stores, offers
//! at enrolment, challenges with and accepts as an answer is its own associated type; the
//! routes, the store and every consumer see only the kind's name and opaque JSON, so a new
//! kind changes nothing outside this module.

mod seal;
mod totp;

use std::{any::Any, marker::PhantomData};

pub(crate) use seal::Binding;
pub use seal::SealKey;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use totp::Totp;

#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::EnumString, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum FactorKind {
	Totp,
}

/// The answer does not prove the factor.
pub(crate) struct Wrong;

pub(crate) trait Factor: 'static {
	/// What is kept, sealed, for the factor: its secret and whatever state verification moves.
	type Material: Serialize + DeserializeOwned;
	/// What is kept, sealed, between the start of an enrolment and its proof.
	type Enrolling: Serialize + DeserializeOwned;
	/// Shown once, at enrolment, so the person can set the factor up on their side.
	type Offer: Serialize;
	/// The proof that ends an enrolment.
	type EnrolResponse: DeserializeOwned;
	/// Sent with a verification's options.
	type Challenge: Serialize;
	/// Held by the ceremony between options and the answer.
	type Pending: Send + 'static;
	type Response: DeserializeOwned;

	fn begin_enrol(account: &str) -> (Self::Enrolling, Self::Offer);
	fn finish_enrol(enrolling: Self::Enrolling, response: Self::EnrolResponse, now: u64) -> Result<Self::Material, Wrong>;
	fn challenge(material: &Self::Material) -> (Self::Challenge, Self::Pending);
	fn verify(material: &mut Self::Material, pending: Self::Pending, response: Self::Response, now: u64) -> Result<(), Wrong>;
}

pub(crate) struct Enrolment {
	/// The kind's [`Factor::Enrolling`], to be sealed.
	pub enrolling: Vec<u8>,
	pub offer: Value,
}

pub(crate) struct Challenged {
	pub challenge: Value,
	pub pending: Box<dyn Any + Send>,
}

pub(crate) enum Checked {
	/// Proven; the material as it must be stored from now on.
	Right(Vec<u8>),
	Wrong,
	/// The answer is not shaped as this kind's answer at all: no guess was made.
	Malformed,
}

/// Stored material that does not read back as its kind's: a write of ours went wrong.
#[derive(Debug)]
pub(crate) struct Corrupt;

impl std::fmt::Display for Corrupt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("second-factor material does not parse as its kind")
	}
}

impl FactorKind {
	pub(crate) fn begin_enrol(self, account: &str) -> Enrolment {
		self.ops().begin_enrol(account)
	}

	/// `Checked::Right` carries the factor's first material.
	pub(crate) fn finish_enrol(self, enrolling: &[u8], response: Value, now: u64) -> Result<Checked, Corrupt> {
		self.ops().finish_enrol(enrolling, response, now)
	}

	pub(crate) fn challenge(self, material: &[u8]) -> Result<Challenged, Corrupt> {
		self.ops().challenge(material)
	}

	pub(crate) fn verify(self, material: &[u8], pending: Box<dyn Any + Send>, response: Value, now: u64) -> Result<Checked, Corrupt> {
		self.ops().verify(material, pending, response, now)
	}

	fn ops(self) -> &'static dyn Ops {
		match self {
			Self::Totp => &As::<Totp>(PhantomData),
		}
	}
}

trait Ops: Sync {
	fn begin_enrol(&self, account: &str) -> Enrolment;
	fn finish_enrol(&self, enrolling: &[u8], response: Value, now: u64) -> Result<Checked, Corrupt>;
	fn challenge(&self, material: &[u8]) -> Result<Challenged, Corrupt>;
	fn verify(&self, material: &[u8], pending: Box<dyn Any + Send>, response: Value, now: u64) -> Result<Checked, Corrupt>;
}

struct As<F>(PhantomData<fn() -> F>);

impl<F: Factor> Ops for As<F> {
	fn begin_enrol(&self, account: &str) -> Enrolment {
		let (enrolling, offer) = F::begin_enrol(account);
		Enrolment {
			enrolling: serde_json::to_vec(&enrolling).expect("enrolment state serializes"),
			offer: serde_json::to_value(offer).expect("an offer serializes"),
		}
	}

	fn finish_enrol(&self, enrolling: &[u8], response: Value, now: u64) -> Result<Checked, Corrupt> {
		let enrolling: F::Enrolling = serde_json::from_slice(enrolling).map_err(|_| Corrupt)?;
		let Ok(response) = serde_json::from_value::<F::EnrolResponse>(response) else {
			return Ok(Checked::Malformed);
		};
		Ok(match F::finish_enrol(enrolling, response, now) {
			Ok(material) => Checked::Right(serde_json::to_vec(&material).expect("material serializes")),
			Err(Wrong) => Checked::Wrong,
		})
	}

	fn challenge(&self, material: &[u8]) -> Result<Challenged, Corrupt> {
		let material: F::Material = serde_json::from_slice(material).map_err(|_| Corrupt)?;
		let (challenge, pending) = F::challenge(&material);
		Ok(Challenged {
			challenge: serde_json::to_value(challenge).expect("a challenge serializes"),
			pending: Box::new(pending),
		})
	}

	fn verify(&self, material: &[u8], pending: Box<dyn Any + Send>, response: Value, now: u64) -> Result<Checked, Corrupt> {
		let mut material: F::Material = serde_json::from_slice(material).map_err(|_| Corrupt)?;
		let pending = *pending.downcast::<F::Pending>().expect("a ceremony is verified by the kind that challenged it");
		let Ok(response) = serde_json::from_value::<F::Response>(response) else {
			return Ok(Checked::Malformed);
		};
		Ok(match F::verify(&mut material, pending, response, now) {
			Ok(()) => Checked::Right(serde_json::to_vec(&material).expect("material serializes")),
			Err(Wrong) => Checked::Wrong,
		})
	}
}
