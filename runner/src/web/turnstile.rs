//! Cloudflare Turnstile, checked on this side: a credential endpoint a script can call
//! freely is a mail cannon and a password oracle. There is no arm that skips it —
//! development configures Cloudflare's always-pass test secret instead, and production
//! refuses to boot with one of those (`is_test_secret`).

use std::time::Duration;

use serde::Deserialize;

pub const SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

pub struct Turnstile {
	secret: String,
	endpoint: String,
	http: reqwest::Client,
}

#[derive(Deserialize)]
struct Verdict {
	success: bool,
	/// The host the challenge was solved on. A token is not bound to a site by itself: one
	/// solved on any page carrying our sitekey would otherwise pass here.
	#[serde(default)]
	hostname: Option<String>,
}

/// Cloudflare's published test secrets — `1x…` always passes, `2x…` always fails, `3x…`
/// answers "token already spent" — `<digit>x`, zeros, `AA`. Their siteverify answers carry
/// a placeholder hostname rather than the page's, so the host check cannot apply to them.
pub fn is_test_secret(secret: &str) -> bool {
	let bytes = secret.as_bytes();
	bytes.len() > 4 && bytes[0].is_ascii_digit() && bytes[1] == b'x' && secret.ends_with("AA") && bytes[2..bytes.len() - 2].iter().all(|b| *b == b'0')
}

impl Turnstile {
	/// `endpoint` is [`SITEVERIFY`] outside a test.
	pub fn new(secret: String, endpoint: String) -> Self {
		Self {
			secret,
			endpoint,
			http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build().expect("a static reqwest client builds"),
		}
	}

	/// `Ok(false)` is Cloudflare saying no, or yes for a challenge solved on a host
	/// `ours` does not claim; `Err` is not being able to ask, which the caller refuses too
	/// — fail closed.
	pub(super) async fn passes(&self, token: &str, remote_ip: &str, ours: impl Fn(&str) -> bool) -> Result<bool, reqwest::Error> {
		if token.is_empty() {
			return Ok(false);
		}
		let mut form = vec![("secret", self.secret.as_str()), ("response", token)];
		if !remote_ip.is_empty() {
			form.push(("remoteip", remote_ip));
		}
		let verdict: Verdict = self.http.post(&self.endpoint).form(&form).send().await?.error_for_status()?.json().await?;
		if !verdict.success {
			return Ok(false);
		}
		if is_test_secret(&self.secret) {
			return Ok(true);
		}
		Ok(verdict.hostname.as_deref().is_some_and(ours))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cloudflare_test_secrets_are_recognised_and_nothing_else() {
		for secret in [
			"1x0000000000000000000000000000000AA",
			"2x0000000000000000000000000000000AA",
			"3x0000000000000000000000000000000AA",
		] {
			assert!(is_test_secret(secret), "{secret}");
		}
		for secret in ["0x4AAAAAAAB0000000000000000000000AA", "1x00000000000000000000000000000001AA", "test-secret", "1xAA", ""] {
			assert!(!is_test_secret(secret), "{secret}");
		}
	}
}
