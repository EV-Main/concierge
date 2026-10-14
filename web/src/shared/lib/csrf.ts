// The double-submit header for the plane's mutating routes. The cookie is host-only to the
// platform origin, so this only ever finds a token on a platform page — which is the only
// place a mutation is offered (config/origin.ts, isPlatformPage).

import { BUILD } from "../config/build";

const CSRF_HEADER = "x-ev-csrf";
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  const found = document.cookie.split("; ").find((entry) => entry.startsWith(prefix));
  if (!found) return null;
  try {
    return decodeURIComponent(found.slice(prefix.length));
  } catch {
    // A malformed `%` sequence would throw out of every request; no token is a refusal the plane already words.
    return null;
  }
}

export function csrfHeader(): Record<string, string> {
  // Production reads the `__Host-` cookie only: a plain `ev_csrf` can be planted from any
  // subdomain, and falling back to it would let that value pass double-submit whenever the
  // real one is missing. The plain name is what a dev plane sets over http.
  const devCookie = BUILD.allowOriginOverride || LOOPBACK.has(location.hostname);
  const token = readCookie("__Host-ev_csrf") ?? (devCookie ? readCookie("ev_csrf") : null);
  return token ? { [CSRF_HEADER]: token } : {};
}
