// `GET /api/auth/session` — who holds the platform session. The one read a scope host may
// make cross-origin (ORG-RESTRUCTURE-PLAN §3.9 F), so every element can show who is
// signed in wherever it is mounted. Shape: concierge's `SessionInfo` (runner/src/web/routes.rs).

import { bool, isRecord, optionalStr, str } from "../lib/guard";
import type { AuthApi } from "./auth-api";

export interface SessionUser {
  userId: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  role: string;
}

export type SessionState =
  | { kind: "loading" }
  /** The plane could not be asked — a blip, not a verdict: nothing signed-out is shown off it. */
  | { kind: "unavailable" }
  | { kind: "anonymous" }
  | { kind: "signedIn"; user: SessionUser };

function parseUser(raw: unknown): SessionUser | null {
  if (!isRecord(raw)) return null;
  const userId = str(raw, "userId");
  const email = str(raw, "email");
  const emailVerified = bool(raw, "emailVerified");
  const username = optionalStr(raw, "username");
  const role = str(raw, "role");
  if (userId === null || email === null || emailVerified === null || username === undefined || role === null) return null;
  return { userId, email, emailVerified, username, role };
}

function parseSession(raw: unknown): SessionState | null {
  if (!isRecord(raw)) return null;
  const authenticated = bool(raw, "authenticated");
  if (authenticated === false) return { kind: "anonymous" };
  if (authenticated !== true) return null;
  const user = parseUser(raw["user"]);
  return user ? { kind: "signedIn", user } : null;
}

export async function readSession(api: AuthApi): Promise<SessionState> {
  const answer = await api.get("/session", parseSession);
  return answer.ok ? answer.body : { kind: "unavailable" };
}
