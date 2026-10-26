import type { Translate } from "@evinvest/i18n";

import type { AuthError } from "../../../shared/api/auth-api";

export function secondFactorRefusal(t: Translate, error: AuthError): string {
  switch (error) {
    case "invalid_answer":
      return t("auth.secondFactor.err.invalidAnswer", "That code is not right. Wait for the next one and try again.");
    case "ceremony_expired":
      return t("auth.secondFactor.err.ceremonyExpired", "That took too long. Enter a new code.");
    case "enrolment_expired":
      return t("auth.secondFactor.err.enrolmentExpired", "That took too long. Start adding the app again.");
    case "factor_locked":
      return t("auth.secondFactor.err.locked", "Too many wrong codes. Try again in a few minutes.");
    case "unknown_factor":
      return t("auth.secondFactor.err.unknownFactor", "That authenticator is no longer on your account. Reload the page.");
    case "no_second_factor":
      return t("auth.secondFactor.err.none", "Your account has no second factor yet.");
    case "too_many_factors":
      return t("auth.secondFactor.err.tooMany", "Your account has as many second factors as it can hold. Remove one first.");
    case "invalid_label":
      return t("auth.secondFactor.err.invalidLabel", "Give it a name of 1–64 characters, on one line.");
    case "invalid_kind":
      return t("auth.secondFactor.err.invalidKind", "This kind of second factor is not supported.");
    case "invalid_request":
      return t("auth.secondFactor.err.invalidRequest", "That answer could not be read. Try again.");
    case "email_unverified":
      return t("auth.secondFactor.err.emailUnverified", "Verify your email before you add a second factor.");
    case "invalid_code":
      return t("auth.secondFactor.err.invalidRecoveryCode", "That recovery code is not right, or was used already.");
    case "reauth_required":
      return t("auth.err.reauthStill", "We could not confirm it is you. Try again.");
    case "second_factor_required":
      return t("auth.secondFactor.err.stillRequired", "We could not confirm your second factor. Try again.");
    case "unauthenticated":
      return t("auth.err.sessionEnded", "Your session has ended. Sign in again.");
    default:
      return t("auth.secondFactor.err.generic", "Something went wrong. Try again.");
  }
}
