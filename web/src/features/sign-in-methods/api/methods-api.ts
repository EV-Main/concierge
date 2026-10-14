// How the signed-in account signs in, and the changes a reader makes to it. Platform pages
// only: these act on an open session, so the plane answers them on its own origin alone
// and they carry the CSRF header (ORG-RESTRUCTURE-PLAN §3.9 F).

import { anyBody, type AuthAnswer, type AuthApi } from "../../../shared/api/auth-api";
import { bool, isRecord, listOf, optionalStr, str } from "../../../shared/lib/guard";
import { prompt, publicKeyOf, creationOptions, registrationJson } from "../../../shared/lib/webauthn";
import { parseCeremony } from "../../../shared/api/code-api";

export interface PasskeySummary {
  id: string;
  name: string;
}

export interface SignInMethods {
  email: string;
  emailVerified: boolean;
  username: string | null;
  password: boolean;
  providers: string[];
  passkeys: PasskeySummary[];
}

function parsePasskey(raw: unknown): PasskeySummary | null {
  if (!isRecord(raw)) return null;
  const id = str(raw, "id");
  const name = str(raw, "name");
  return id !== null && name !== null ? { id, name } : null;
}

function parseMethods(raw: unknown): SignInMethods | null {
  if (!isRecord(raw)) return null;
  const email = str(raw, "email");
  const emailVerified = bool(raw, "emailVerified");
  const username = optionalStr(raw, "username");
  const password = bool(raw, "password");
  const providers = listOf(raw["providers"], (p) => (typeof p === "string" ? p : null));
  const passkeys = listOf(raw["passkeys"], parsePasskey);
  if (email === null || emailVerified === null || username === undefined || password === null || !providers || !passkeys) return null;
  return { email, emailVerified, username, password, providers, passkeys };
}

export const readMethods = (api: AuthApi) => api.get("/methods", parseMethods);

/** Mail the signed-in account a code for its own address (it also arms `/password/set`). */
export const requestVerification = (api: AuthApi) => api.send("POST", "/email/verify/request", {}, anyBody, true);

/**
 * Prove the account's address. Not `/code/verify`: that opens a session for whoever holds
 * the mailbox, where this acts on the session the reader already has.
 */
export const confirmVerification = (api: AuthApi, code: string) => api.send("POST", "/email/verify/confirm", { code }, anyBody, true);

/** A new password costs a mailed code: one a stolen session could plant without it would outlive the session's revocation. */
export const setPassword = (api: AuthApi, password: string, code: string) => api.send("POST", "/password/set", { password, code }, anyBody, true);

export const setUsername = (api: AuthApi, username: string) => api.send("POST", "/username", { username }, anyBody, true);

export const removePasskey = (api: AuthApi, credentialId: string) => api.send("POST", "/passkey/remove", { credentialId }, anyBody, true);

/** Register a passkey for the signed-in account under `name`. */
export async function addPasskey(api: AuthApi, name: string): Promise<AuthAnswer<true>> {
  const begun = await api.send("POST", "/passkey/register/options", {}, parseCeremony, true);
  if (!begun.ok) return begun;
  const pk = publicKeyOf(begun.body.options);
  const options = pk ? creationOptions(pk) : null;
  if (!options) return { ok: false, error: "internal" };
  const credential = await prompt(() => navigator.credentials.create(options));
  const json = credential ? registrationJson(credential) : null;
  if (!json) return { ok: false, error: "passkey_cancelled" };
  return api.send("POST", "/passkey/register/verify", { ceremony: begun.body.ceremony, credential: json, name }, anyBody, true);
}
