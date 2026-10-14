// Signing in with an emailed code, on every host. `/code/request` spends a Turnstile token.
// Not a way to confirm a new account's address: `/code/verify` opens a session for whoever
// holds the mailbox, so the sign-up confirmation has its own ticketed routes
// (features/sign-in/api/sign-in-api.ts).

import { isRecord, str } from "../lib/guard";
import { anyBody, type AuthApi } from "./auth-api";

export const requestCode = (api: AuthApi, email: string, turnstileToken: string) => api.send("POST", "/code/request", { email, turnstileToken }, anyBody);

export const verifyCode = (api: AuthApi, email: string, code: string) => api.send("POST", "/code/verify", { email, code }, anyBody);

/** A WebAuthn ceremony as the plane opens one: its handle and the options for the browser. */
export interface Ceremony {
  ceremony: string;
  options: unknown;
}

export function parseCeremony(raw: unknown): Ceremony | null {
  if (!isRecord(raw)) return null;
  const ceremony = str(raw, "ceremony");
  return ceremony ? { ceremony, options: raw["options"] } : null;
}
