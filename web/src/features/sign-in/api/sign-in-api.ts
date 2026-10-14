// The sign-in steps. These — and `GET /session` — are the only routes the plane answers
// cross-origin, for the registered scope origins (ORG-RESTRUCTURE-PLAN §4.1, §3.9 F), so
// the dialog works on every host. None carries the CSRF header: there is no session yet.

import { anyBody, type AuthAnswer, type AuthApi } from "../../../shared/api/auth-api";
import { parseCeremony } from "../../../shared/api/code-api";
import { isRecord } from "../../../shared/lib/guard";
import { assertionJson, prompt, publicKeyOf, requestOptions } from "../../../shared/lib/webauthn";

export { requestCode, verifyCode } from "../../../shared/api/code-api";

export type Verification = "sent" | "skipped" | "throttled" | "failed";
const VERIFICATIONS: readonly Verification[] = ["sent", "skipped", "throttled", "failed"];

function parseSignUp(raw: unknown): Verification | null {
  const value = isRecord(raw) ? raw["verification"] : undefined;
  return VERIFICATIONS.find((v) => v === value) ?? null;
}

export const passwordSignIn = (api: AuthApi, identifier: string, password: string, turnstileToken: string) =>
  api.send("POST", "/password/signin", { identifier, password, turnstileToken }, anyBody);

/**
 * `verify: false` always: the plane's own verification mail is confirmed through
 * /email/verify/*, which is CSRF-checked and so unusable from a scope host. The dialog
 * proves the address the same way everywhere instead — /code/request + /code/verify, whose
 * verify marks the address verified.
 */
export const passwordSignUp = (api: AuthApi, email: string, password: string, turnstileToken: string) =>
  api.send("POST", "/password/signup", { email, password, verify: false, turnstileToken }, parseSignUp);

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
