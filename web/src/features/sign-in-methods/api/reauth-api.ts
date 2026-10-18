// Re-authentication: the signed-in account proves itself again and the session's `auth_time`
// moves to now (runner/src/web/reauth.rs). Platform pages only, CSRF-checked like every
// session route. A success answers `{"ok":true,"authTime":N}`; nothing here reads the
// number, because the plane re-sets the access cookie and the retried act is what checks it.

import { anyBody, type AuthAnswer, type AuthApi } from "../../../shared/api/auth-api";
import { parseCeremony } from "../../../shared/api/code-api";
import { assertionJson, prompt, publicKeyOf, requestOptions } from "../../../shared/lib/webauthn";

/** Mail the account a re-authentication code. Spends a Turnstile token, as every mail does. */
export const requestReauthCode = (api: AuthApi, turnstileToken: string) => api.send("POST", "/reauth/code/request", { turnstileToken }, anyBody, true);

export const verifyReauthCode = (api: AuthApi, code: string) => api.send("POST", "/reauth/code/verify", { code }, anyBody, true);

export const reauthWithPassword = (api: AuthApi, password: string) => api.send("POST", "/reauth/password", { password }, anyBody, true);

/** Assert one of the account's own passkeys (the plane names them; none is discoverable). */
export async function reauthWithPasskey(api: AuthApi): Promise<AuthAnswer<true>> {
  const begun = await api.send("POST", "/reauth/passkey/options", {}, parseCeremony, true);
  if (!begun.ok) return begun;
  const pk = publicKeyOf(begun.body.options);
  const options = pk ? requestOptions(pk) : null;
  if (!options) return { ok: false, error: "internal" };
  const credential = await prompt(() => navigator.credentials.get(options));
  const json = credential ? assertionJson(credential) : null;
  if (!json) return { ok: false, error: "passkey_cancelled" };
  return api.send("POST", "/reauth/passkey/verify", { ceremony: begun.body.ceremony, credential: json }, anyBody, true);
}
