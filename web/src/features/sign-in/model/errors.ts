import type { Translate } from "@evinvest/i18n";

import type { AuthError } from "../../../shared/api/auth-api";

export function errorText(t: Translate, error: AuthError | "captcha_load"): string {
  switch (error) {
    case "invalid_code":
      return t("auth.err.invalidCode", "That code is not right. Try again.");
    case "attempts_exceeded":
      return t("auth.err.attemptsExceeded", "Too many tries. Send yourself a new code.");
    case "code_expired":
      return t("auth.err.codeExpired", "That code has expired. Send yourself a new code.");
    case "throttled":
      return t("auth.err.throttled", "Too many codes went to this address. Try again in a few minutes.");
    case "captcha":
      return t("auth.err.captcha", "Captcha verification failed. Please try again.");
    case "captcha_unavailable":
      return t("auth.err.captchaUnavailable", "We could not check the captcha just now. Please try again.");
    case "captcha_load":
      return t("auth.err.captchaLoad", "Captcha failed to load. Please refresh the page.");
    case "invalid_email":
      return t("auth.err.invalidEmail", "Enter a valid email address.");
    case "email_taken":
      return t("auth.err.emailTaken", "An account already exists for that address. Sign in instead — with a code if you forgot the password.");
    case "weak_password":
      return t("auth.err.weakPassword", "Use at least 8 characters.");
    case "invalid_credentials":
      return t("auth.err.invalidCredentials", "Wrong email, username or password.");
    case "password_locked":
      return t("auth.err.passwordLocked", "Too many wrong passwords. Sign in with a code instead.");
    case "disabled":
      return t("auth.err.disabled", "This account is suspended.");
    case "passkey_cancelled":
      return t("auth.err.passkeyCancelled", "Passkey sign in was cancelled.");
    case "passkey_rejected":
      return t("auth.err.passkeyRejected", "That passkey is not registered here. Sign in with a code instead.");
    case "passkey_expired":
      return t("auth.err.passkeyExpired", "That took too long. Try the passkey again.");
    default:
      return t("auth.err.generic", "Sign-in failed. Please try again.");
  }
}

/** What an OAuth round trip that failed puts on the page it returns to (`?auth_error=`). */
export function oauthErrorText(t: Translate, reason: string): string {
  switch (reason) {
    case "denied":
      return t("auth.err.denied", "Sign-in was cancelled.");
    case "invalid":
      return t("auth.err.invalid", "That sign-in attempt expired. Please try again.");
    case "exchange":
      return t("auth.err.exchange", "We couldn't complete sign-in. Please try again.");
    case "disabled":
      return errorText(t, "disabled");
    default:
      return errorText(t, "internal");
  }
}
