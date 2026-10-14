// The account's live sessions (refresh-token families) and revoking one. Platform pages
// only, like every action on an open session.

import { anyBody, type AuthApi } from "../../../shared/api/auth-api";
import { bool, isRecord, listOf, str } from "../../../shared/lib/guard";

export interface Session {
  id: string;
  userAgent: string;
  ip: string;
  /** Unix seconds; the plane sends them as decimal strings. */
  lastSeen: number;
  current: boolean;
}

function parseSession(raw: unknown): Session | null {
  if (!isRecord(raw)) return null;
  const id = str(raw, "id");
  const userAgent = str(raw, "user_agent");
  const ip = str(raw, "ip");
  const lastSeen = str(raw, "last_seen");
  const current = bool(raw, "current");
  if (id === null || userAgent === null || ip === null || lastSeen === null || current === null) return null;
  return { id, userAgent, ip, lastSeen: Number(lastSeen), current };
}

export const listSessions = (api: AuthApi) => api.get("/sessions", (raw) => (isRecord(raw) ? listOf(raw["sessions"], parseSession) : null));

export const revokeSession = (api: AuthApi, sessionId: string) => api.send("DELETE", "/sessions", { session_id: sessionId }, anyBody, true);
