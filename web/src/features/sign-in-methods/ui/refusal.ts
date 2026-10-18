import type { Translate } from "@evinvest/i18n";

import type { AuthError } from "../../../shared/api/auth-api";

export function refusal(t: Translate, error: AuthError): string {
  switch (error) {
    case "invalid_code":
      return t("auth.err.invalidCode", "That code is not right. Try again.");
    case "attempts_exceeded":
      return t("auth.err.attemptsExceeded", "Too many tries. Send yourself a new code.");
    case "code_expired":
      return t("auth.err.codeExpired", "That code has expired. Send yourself a new code.");
    case "throttled":
      return t("auth.err.throttled", "Too many codes went to this address. Try again in a few minutes.");
    case "email_taken":
      return t("auth.err.emailVerifiedElsewhere", "This address is verified on another account.");
    case "weak_password":
      return t("auth.err.weakPassword", "Use at least 8 characters.");
    case "invalid_username":
      return t("auth.err.invalidUsername", "3–32 characters: letters, digits, '_', '.' or '-'.");
    case "username_taken":
      return t("auth.err.usernameTaken", "That username is taken.");
    case "passkey_cancelled":
      return t("auth.err.passkeyCancelled", "Passkey sign in was cancelled.");
    case "passkey_registered":
      return t("auth.err.passkeyRegistered", "This passkey is registered already.");
    case "reauth_required":
      return t("auth.err.reauthStill", "We could not confirm it is you. Try again.");
    case "unauthenticated":
      return t("auth.err.sessionEnded", "Your session has ended. Sign in again.");
    default:
      return t("auth.err.generic", "Sign-in failed. Please try again.");
  }
}

/**
 * The refusals of the confirmation step. Its words differ from sign-in's where the same code
 * means something else here: `throttled` counts attempts, not mailed codes, and a rejected
 * passkey is one that cannot vouch for THIS session.
 */
export function reauthRefusal(t: Translate, error: AuthError): string {
  switch (error) {
    case "throttled":
      return t("auth.reauth.err.throttled", "Too many attempts. Try again in a few minutes.");
    case "email_unverified":
      return t("auth.reauth.err.emailUnverified", "Your email is not verified, so we cannot mail you a code. Confirm another way.");
    case "retry":
      return t("auth.reauth.err.retry", "Your session was refreshed at the same moment. Try once more.");
    case "no_passkey":
      return t("auth.reauth.err.noPasskey", "None of your passkeys can confirm this session. Use a code or your password.");
    case "passkey_rejected":
      return t("auth.reauth.err.passkeyRejected", "That passkey could not confirm this session.");
    case "passkey_cancelled":
      return t("auth.reauth.err.passkeyCancelled", "Passkey confirmation was cancelled.");
    case "passkey_expired":
      return t("auth.err.passkeyExpired", "That took too long. Try the passkey again.");
    case "invalid_credentials":
      return t("auth.reauth.err.invalidPassword", "That password is not right.");
    case "password_locked":
      return t("auth.reauth.err.passwordLocked", "Too many wrong passwords. Confirm with a code instead.");
    case "captcha":
      return t("auth.err.captcha", "Captcha verification failed. Please try again.");
    case "captcha_unavailable":
      return t("auth.err.captchaUnavailable", "We could not check the captcha just now. Please try again.");
    case "origin":
      return t("auth.reauth.err.origin", "Confirm from the platform page of your account.");
    case "disabled":
      return t("auth.err.disabled", "This account is suspended.");
    default:
      return refusal(t, error);
  }
}
