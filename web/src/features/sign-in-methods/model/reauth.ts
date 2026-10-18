// The decisions of the re-authentication step, kept free of React so they can be tested
// on their own: what to do with an answer, and which ways of confirming to offer.

import type { AuthAnswer, AuthError } from "../../../shared/api/auth-api";

export type ReauthMethod = "code" | "password" | "passkey";

/** What the panel does with the answer of a sensitive act. */
export type Outcome = { step: "done" } | { step: "reauth" } | { step: "error"; error: AuthError };

/**
 * `reauth_required` asks for a confirmation once. When the act is refused that way again
 * AFTER a confirmation, asking again would loop on a session the plane keeps rejecting, so
 * the reader gets the error instead.
 */
export function outcomeOf(answer: AuthAnswer<true>, confirmedBefore: boolean): Outcome {
  if (answer.ok) return { step: "done" };
  if (answer.error === "reauth_required" && !confirmedBefore) return { step: "reauth" };
  return { step: "error", error: answer.error };
}

export interface ReauthFacts {
  emailVerified: boolean;
  password: boolean;
  passkeys: number;
}

/**
 * The ways the account can confirm. A code goes only to a VERIFIED address (the plane
 * refuses `email_unverified` otherwise), and a passkey needs the browser to speak WebAuthn.
 */
export function reauthMethods(facts: ReauthFacts, webauthn: boolean): ReauthMethod[] {
  const methods: ReauthMethod[] = [];
  if (facts.emailVerified) methods.push("code");
  if (facts.password) methods.push("password");
  if (webauthn && facts.passkeys > 0) methods.push("passkey");
  return methods;
}

export function isReauthMethod(value: string): value is ReauthMethod {
  return value === "code" || value === "password" || value === "passkey";
}
