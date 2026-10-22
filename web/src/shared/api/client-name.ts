// `GET /api/auth/clients/{client_id}` — the registered name of the app a confirmation is
// for (`runner/src/web/authorize.rs`, `client_name`). Same-origin and public, so it is
// asked without credentials. Only a 404 is a verdict: every other failure leaves the page
// generic, because a blip must not block a confirmation the authorize route would serve.

import { isRecord, str } from "../lib/guard";

export type ClientName =
  | { kind: "named"; name: string }
  /** No name to show: the scope set none, or the plane could not be asked. */
  | { kind: "unnamed" }
  /** concierge would not serve this client at authorize, so no code can come of the trip. */
  | { kind: "unknown" };

const TIMEOUT_MS = 5000;

/** `clientsUrl` is the directory the lookup lives in, ending in `/`. */
export async function fetchClientName(clientsUrl: URL, clientId: string): Promise<ClientName> {
  let response: Response;
  try {
    response = await fetch(new URL(encodeURIComponent(clientId), clientsUrl), {
      credentials: "omit",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    return { kind: "unnamed" };
  }
  if (response.status === 404) return { kind: "unknown" };
  if (!response.ok) return { kind: "unnamed" };
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { kind: "unnamed" };
  }
  if (!isRecord(body) || str(body, "client_id") !== clientId) return { kind: "unnamed" };
  const name = str(body, "display_name")?.trim();
  return name ? { kind: "named", name } : { kind: "unnamed" };
}
