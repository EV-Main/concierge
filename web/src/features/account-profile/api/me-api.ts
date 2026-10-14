// `GET /api/auth/me` — who the signed-in account is, without anything an identity document
// holds. Platform origin only (not on the scope CORS list); a scope host shows the session.

import type { AuthApi } from "../../../shared/api/auth-api";
import { bool, isRecord, optionalStr, str } from "../../../shared/lib/guard";

export interface Me {
  id: string;
  email: string;
  emailVerified: boolean;
  username: string | null;
  preferredName: string | null;
  role: string;
  /** The role comes from the emergency allowlist, not the account: temporary, and it seats nobody. */
  breakGlass: boolean;
  kycLevel: number;
}

function parseMe(raw: unknown): Me | null {
  if (!isRecord(raw)) return null;
  const id = str(raw, "id");
  const email = str(raw, "email");
  const emailVerified = bool(raw, "email_verified");
  const username = optionalStr(raw, "username");
  const preferredName = optionalStr(raw, "preferred_name");
  const role = str(raw, "role");
  const breakGlass = bool(raw, "role_is_break_glass");
  const kycLevel = raw["kyc_level"];
  if (id === null || email === null || emailVerified === null || username === undefined || preferredName === undefined || role === null || breakGlass === null) return null;
  if (typeof kycLevel !== "number" || !Number.isInteger(kycLevel)) return null;
  return { id, email, emailVerified, username, preferredName, role, breakGlass, kycLevel };
}

export const readMe = (api: AuthApi) => api.get("/me", parseMe);
