// Sign out in default mode, which only a platform page can do: the logout is CSRF-checked
// and the token cookie is readable on the platform origin alone. Only a 2xx means the
// session is gone — a refusal or a dropped connection leaves it alive, and pretending
// otherwise would lie to someone walking away from a shared machine.

import { anyBody, type AuthApi } from "../../../shared/api/auth-api";

export async function signOut(api: AuthApi): Promise<boolean> {
  const answer = await api.send("POST", "/logout", {}, anyBody, true);
  return answer.ok;
}
