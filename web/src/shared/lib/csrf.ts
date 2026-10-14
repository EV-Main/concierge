// The double-submit header for the plane's mutating routes. The cookie is host-only to the
// platform origin, so this only ever finds a token on a platform page — which is the only
// place a mutation is offered (config/origin.ts, isPlatformPage).

const CSRF_HEADER = "x-ev-csrf";

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
  // The `__Host-` cookie first, so a plain `ev_csrf` planted from a subdomain cannot shadow it.
  const token = readCookie("__Host-ev_csrf") ?? readCookie("ev_csrf");
  return token ? { [CSRF_HEADER]: token } : {};
}
