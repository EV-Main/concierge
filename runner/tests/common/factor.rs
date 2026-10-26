//! An authenticator app played by RFC 6238 computed here, from the secret an enrolment
//! offers, and the account that enrolled one.

use axum::http::StatusCode;
use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::{Value, json};
use sha1::Sha1;

use super::web::{Answer, Browser, ORIGIN, Surface, address};

pub fn now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// What an authenticator app shows for `secret` (base32) `steps` thirty-second steps from now.
pub fn app_code(secret: &str, steps: i64) -> String {
	let key = data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
	let counter = (now() / 30).checked_add_signed(steps).unwrap();
	let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(&key).unwrap();
	mac.update(&counter.to_be_bytes());
	let digest = mac.finalize().into_bytes();
	let offset = (digest[19] & 0x0f) as usize;
	let binary = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
	format!("{:06}", binary % 1_000_000)
}

/// A wrong code that cannot collide with the right one in any accepted step.
pub fn wrong(secret: &str) -> String {
	let right: Vec<String> = (-1..=1).map(|s| app_code(secret, s)).collect();
	(0..10).map(|d| d.to_string().repeat(6)).find(|c| !right.contains(c)).unwrap()
}

/// A signed-in account, its browser, and the secret of the authenticator it enrolled.
pub struct Holder {
	pub browser: Browser,
	pub email: String,
	pub user: uuid::Uuid,
	pub secret: String,
	pub factor: String,
	pub recovery: Vec<String>,
}

pub fn refusal(answer: &Answer) -> (StatusCode, Value) {
	(answer.status, answer.body.clone())
}

pub fn error(status: StatusCode, code: &str) -> (StatusCode, Value) {
	(status, json!({ "error": code }))
}

impl Surface {
	pub async fn signed_in(&self, tag: &str) -> (Browser, String) {
		let email = address(tag);
		let mut browser = Browser::default();
		let signed = self.sign_in_with_code(&email, &mut browser).await;
		assert_eq!(signed.status, StatusCode::OK, "{:?}", signed.body);
		(browser, email)
	}

	pub async fn enrol_start(&self, browser: &mut Browser) -> Answer {
		self.post("/auth/second-factor/enrol/start", ORIGIN, json!({ "kind": "totp", "label": "Phone" }), browser).await
	}

	pub async fn enrol(&self, browser: &mut Browser) -> (String, Answer) {
		let started = self.enrol_start(browser).await;
		assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
		let secret = started.body["offer"]["secret"].as_str().unwrap().to_owned();
		let confirmed = self
			.post(
				"/auth/second-factor/enrol/confirm",
				ORIGIN,
				json!({ "enrolment": started.body["enrolment"], "response": { "code": app_code(&secret, 0) } }),
				browser,
			)
			.await;
		(secret, confirmed)
	}

	pub async fn holder(&self, tag: &str) -> Holder {
		let (mut browser, email) = self.signed_in(tag).await;
		let (secret, confirmed) = self.enrol(&mut browser).await;
		assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body);
		let recovery = confirmed.body["recoveryCodes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect();
		let methods = self.get("/auth/methods", &mut browser).await;
		let factor = methods.body["secondFactor"]["factors"][0]["id"].as_str().unwrap().to_owned();
		let user = sqlx::query_scalar("SELECT id FROM users WHERE email = $1").bind(&email).fetch_one(&self.pool).await.unwrap();
		Holder {
			browser,
			email,
			user,
			secret,
			factor,
			recovery,
		}
	}

	/// Open a verification ceremony and answer `code` to the holder's factor.
	pub async fn prove(&self, who: &mut Holder, code: &str) -> Answer {
		let options = self.post("/auth/second-factor/verify/options", ORIGIN, json!({}), &mut who.browser).await;
		assert_eq!(options.status, StatusCode::OK, "{:?}", options.body);
		self.post(
			"/auth/second-factor/verify",
			ORIGIN,
			json!({ "ceremony": options.body["ceremony"], "factor": who.factor, "response": { "code": code } }),
			&mut who.browser,
		)
		.await
	}

	pub async fn notices(&self, email: &str) -> Vec<String> {
		sqlx::query_scalar("SELECT payload->>'event' FROM notification_deliveries WHERE kind = 'security_notice' AND recipient = $1 ORDER BY id")
			.bind(email)
			.fetch_all(&self.pool)
			.await
			.unwrap()
	}
}
