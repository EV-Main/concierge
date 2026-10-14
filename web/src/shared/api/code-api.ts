// The email-code steps, shared by sign-in and by proving an address: `/code/verify` both
// signs the reader in and marks the address verified, and unlike /email/verify/* it needs
// no CSRF token, so it is one path on every host. `/code/request` spends a Turnstile token.

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
