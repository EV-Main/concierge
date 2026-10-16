// The sign-in steps. These — and `GET /session` — are the only routes the plane answers
// cross-origin, for the registered scope origins (ORG-RESTRUCTURE-PLAN §4.1, §3.9 F), so
// the dialog works on every host. None carries the CSRF header: there is no session yet.

import { anyBody, type AuthAnswer, type AuthApi } from "../../../shared/api/auth-api";
import { parseCeremony } from "../../../shared/api/code-api";
import { isRecord, optionalStr } from "../../../shared/lib/guard";
import { assertionJson, prompt, publicKeyOf, requestOptions } from "../../../shared/lib/webauthn";

export { requestCode, verifyCode } from "../../../shared/api/code-api";

export type Verification = "sent" | "skipped" | "throttled" | "failed";
const VERIFICATIONS: readonly Verification[] = ["sent", "skipped", "throttled", "failed"];

export interface SignUpAnswer {
  verification: Verification;
  /**
   * Lets this browser confirm the mailed code without the CSRF cookie, which a scope host
   * cannot read. Null with `ticketLost` when the plane made the account but could not
   * store one: the address is then confirmed on the platform.
   */
  ticket: string | null;
  ticketLost: boolean;
}

function parseSignUp(raw: unknown): SignUpAnswer | null {
  if (!isRecord(raw)) return null;
  const verification = VERIFICATIONS.find((v) => v === raw["verification"]);
  const ticket = optionalStr(raw, "ticket");
  if (!verification || ticket === undefined) return null;
  return { verification, ticket, ticketLost: raw["ticket_error"] === "ticket_unavailable" };
}

export const passwordSignIn = (api: AuthApi, identifier: string, password: string, turnstileToken: string) =>
  api.send("POST", "/password/signin", { identifier, password, turnstileToken }, anyBody);

/** Signs the new account in at once; with `verify` it also mails a code and hands back a ticket. */
export const passwordSignUp = (api: AuthApi, email: string, password: string, verify: boolean, turnstileToken: string) =>
  api.send("POST", "/password/signup", { email, password, verify, turnstileToken }, parseSignUp);

/** Confirm the new account's address with the mailed code; no Turnstile, the ticket is the proof. */
export const confirmSignUp = (api: AuthApi, ticket: string, code: string) => api.send("POST", "/password/signup/confirm", { ticket, code }, anyBody);

export const resendSignUpCode = (api: AuthApi, ticket: string, turnstileToken: string) => api.send("POST", "/password/signup/resend", { ticket, turnstileToken }, anyBody);

/** Sign in with whichever passkey the reader picks; it names the account. */
export async function passkeySignIn(api: AuthApi): Promise<AuthAnswer<true>> {
  const begun = await api.send("POST", "/passkey/signin/options", {}, parseCeremony);
  if (!begun.ok) return begun;
  const pk = publicKeyOf(begun.body.options);
  const options = pk ? requestOptions(pk) : null;
  if (!options) return { ok: false, error: "internal" };
  const credential = await prompt(() => navigator.credentials.get(options));
  const json = credential ? assertionJson(credential) : null;
  if (!json) return { ok: false, error: "passkey_cancelled" };
  return api.send("POST", "/passkey/signin/verify", { ceremony: begun.body.ceremony, credential: json }, anyBody);
}

/** The OAuth providers the plane signs in through, by their `?provider=` name. */
export const PROVIDERS = ["google", "github"] as const;
export type Provider = (typeof PROVIDERS)[number];
