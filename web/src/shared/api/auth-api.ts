// The identity plane's browser surface, `<origin>/api/auth/*` (the conductor rewrites it to
// concierge's /auth/*). Every request carries `credentials: "include"`: on a scope host the
// call is cross-origin and the session cookie is first-party to the platform only.
//
// Every answer is `{"ok":true,…}` or `{"error":"<code>"}` from one closed vocabulary. A few
// routes still refuse in plain text (logout, sessions); those are read by status.

import { csrfHeader } from "../lib/csrf";
import { isRecord } from "../lib/guard";

export const AUTH_ERRORS = [
  "origin",
  "captcha",
  "captcha_unavailable",
  "invalid_email",
  "throttled",
  "invalid_code",
  "code_expired",
  "attempts_exceeded",
  "email_taken",
  "weak_password",
  "invalid_credentials",
  "password_locked",
  "disabled",
  "unauthenticated",
  "csrf",
  "invalid_username",
  "username_taken",
  "passkey_expired",
  "passkey_rejected",
  "passkey_registered",
  "passkey_cancelled",
  "invalid_ticket",
  "invalid_channel",
  "unknown_topic",
  "unavailable",
  "internal",
] as const;

export type AuthError = (typeof AUTH_ERRORS)[number];

export type AuthAnswer<T> = { ok: true; body: T } | { ok: false; error: AuthError };

function isAuthError(value: unknown): value is AuthError {
  return AUTH_ERRORS.some((code) => code === value);
}

function byStatus(status: number): AuthError {
  if (status === 401) return "unauthenticated";
  if (status === 403) return "csrf";
  if (status === 404 || status === 501 || status === 503) return "unavailable";
  if (status === 429) return "throttled";
  return "internal";
}

/** A body that fails `parse` is an `internal` refusal: the plane said something we cannot read. */
export type Parse<T> = (raw: unknown) => T | null;

/** For routes whose success body carries nothing the caller reads. */
export const anyBody: Parse<true> = () => true;

export interface AuthApi {
  readonly origin: string;
  get<T>(path: string, parse: Parse<T>): Promise<AuthAnswer<T>>;
  /** `session`: the call acts on the signed-in account and carries the CSRF header. */
  send<T>(method: "POST" | "DELETE", path: string, body: unknown, parse: Parse<T>, session?: boolean): Promise<AuthAnswer<T>>;
}

async function answer<T>(request: Promise<Response>, parse: Parse<T>): Promise<AuthAnswer<T>> {
  let res: Response;
  try {
    res = await request;
  } catch {
    return { ok: false, error: "internal" };
  }
  const json: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const code = isRecord(json) ? json["error"] : undefined;
    return { ok: false, error: isAuthError(code) ? code : byStatus(res.status) };
  }
  const body = parse(json);
  return body === null ? { ok: false, error: "internal" } : { ok: true, body };
}

export function authApi(origin: string): AuthApi {
  const base = `${origin}/api/auth`;
  return {
    origin,
    get: (path, parse) =>
      answer(fetch(`${base}${path}`, { credentials: "include", cache: "no-store", headers: { accept: "application/json" } }), parse),
    send: (method, path, body, parse, session = false) =>
      answer(
        fetch(`${base}${path}`, {
          method,
          credentials: "include",
          headers: { "content-type": "application/json", accept: "application/json", ...(session ? csrfHeader() : {}) },
          body: JSON.stringify(body),
        }),
        parse,
      ),
  };
}
