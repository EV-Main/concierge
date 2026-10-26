//! An authenticator app (RFC 6238): HMAC-SHA-1, six digits, thirty-second steps — the
//! parameters every such app computes, so none is offered as a choice.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac, digest::KeyInit};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use super::{Factor, Wrong};

const STEP_SECS: u64 = 30;
const DIGITS: usize = 6;
/// Steps either side of now still accepted: a phone's clock and a person's typing.
const SKEW_STEPS: u64 = 1;
/// RFC 4226's recommended secret length for SHA-1.
const SECRET_BYTES: usize = 20;
const ISSUER: &str = "EV Investment";

pub(crate) struct Totp;

#[derive(Deserialize, Serialize)]
pub(crate) struct Material {
	secret: Vec<u8>,
	/// The step of the last accepted code: a code is accepted once, and never one older.
	last_step: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct Offer {
	uri: String,
	secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
	code: String,
}

impl Factor for Totp {
	type Challenge = ();
	type EnrolResponse = Response;
	type Enrolling = Material;
	type Material = Material;
	type Offer = Offer;
	type Pending = ();
	type Response = Response;

	fn begin_enrol(account: &str) -> (Material, Offer) {
		let mut secret = vec![0u8; SECRET_BYTES];
		getrandom::fill(&mut secret).expect("CSPRNG unavailable");
		let encoded = BASE32_NOPAD.encode(&secret);
		let label: String = form_urlencoded::byte_serialize(format!("{ISSUER}:{account}").as_bytes()).collect();
		let issuer: String = form_urlencoded::byte_serialize(ISSUER.as_bytes()).collect();
		// `byte_serialize` writes a space as `+`, which an otpauth path does not decode.
		let uri = format!(
			"otpauth://totp/{}?secret={encoded}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
			label.replace('+', "%20"),
			issuer.replace('+', "%20")
		);
		(Material { secret, last_step: None }, Offer { uri, secret: encoded })
	}

	/// The first code proves the app holds the secret, and is the last one accepted so far.
	fn finish_enrol(mut enrolling: Material, response: Response, now: u64) -> Result<Material, Wrong> {
		Self::verify(&mut enrolling, (), response, now)?;
		Ok(enrolling)
	}

	fn challenge(_: &Material) -> ((), ()) {
		((), ())
	}

	fn verify(material: &mut Material, (): (), response: Response, now: u64) -> Result<(), Wrong> {
		let code = response.code.trim();
		if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
			return Err(Wrong);
		}
		let current = now / STEP_SECS;
		let accepted = (current.saturating_sub(SKEW_STEPS)..=current + SKEW_STEPS)
			.filter(|step| material.last_step.is_none_or(|last| *step > last))
			.filter(|step| bool::from(code_at(&material.secret, *step).as_bytes().ct_eq(code.as_bytes())))
			.max();
		match accepted {
			Some(step) => {
				material.last_step = Some(step);
				Ok(())
			}
			None => Err(Wrong),
		}
	}
}

/// RFC 4226 §5.3: HOTP of `counter`, dynamically truncated to [`DIGITS`].
fn code_at(secret: &[u8], counter: u64) -> String {
	let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC accepts a key of any length");
	mac.update(&counter.to_be_bytes());
	let digest = mac.finalize().into_bytes();
	let offset = (digest[digest.len() - 1] & 0x0f) as usize;
	let binary = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
	format!("{:0width$}", binary % 10u32.pow(DIGITS as u32), width = DIGITS)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// RFC 6238 Appendix B, SHA-1 rows (the eight-digit values, kept to their last six).
	#[test]
	fn the_rfc_vectors_hold() {
		let secret = b"12345678901234567890";
		for (time, eight) in [
			(59u64, "94287082"),
			(1_111_111_109, "07081804"),
			(1_111_111_111, "14050471"),
			(1_234_567_890, "89005924"),
			(2_000_000_000, "69279037"),
			(20_000_000_000, "65353130"),
		] {
			assert_eq!(code_at(secret, time / STEP_SECS), eight[2..], "T = {time}");
		}
	}

	fn material() -> Material {
		Material {
			secret: b"12345678901234567890".to_vec(),
			last_step: None,
		}
	}

	fn answer(code: &str) -> Response {
		Response { code: code.into() }
	}

	#[test]
	fn a_code_counts_once_and_an_older_one_never_after_it() {
		let mut m = material();
		let now = 1_234_567_890;
		let current = code_at(&m.secret, now / STEP_SECS);
		let previous = code_at(&m.secret, now / STEP_SECS - 1);
		assert!(Totp::verify(&mut m, (), answer(&current), now).is_ok());
		assert!(Totp::verify(&mut m, (), answer(&current), now).is_err(), "replayed");
		assert!(Totp::verify(&mut m, (), answer(&previous), now).is_err(), "older than the last accepted");
	}

	#[test]
	fn one_step_of_skew_either_way_and_no_more() {
		let now = 1_234_567_890;
		let at = |offset: i64| code_at(b"12345678901234567890", (now / STEP_SECS).checked_add_signed(offset).unwrap());
		assert!(Totp::verify(&mut material(), (), answer(&at(-1)), now).is_ok());
		assert!(Totp::verify(&mut material(), (), answer(&at(1)), now).is_ok());
		assert!(Totp::verify(&mut material(), (), answer(&at(-2)), now).is_err());
		assert!(Totp::verify(&mut material(), (), answer(&at(2)), now).is_err());
	}

	#[test]
	fn the_offer_names_the_secret_it_stores() {
		let (m, offer) = Totp::begin_enrol("person@example.com");
		assert_eq!(BASE32_NOPAD.decode(offer.secret.as_bytes()).unwrap(), m.secret);
		assert!(offer.uri.starts_with("otpauth://totp/EV%20Investment%3Aperson%40example.com?secret="), "{}", offer.uri);
		assert!(offer.uri.ends_with("&issuer=EV%20Investment&algorithm=SHA1&digits=6&period=30"), "{}", offer.uri);
	}
}
