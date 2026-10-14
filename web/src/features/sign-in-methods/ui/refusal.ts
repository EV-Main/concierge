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
    default:
      return t("auth.err.generic", "Sign-in failed. Please try again.");
  }
}
