// Where the platform confirmation page (`reauth.html`) sends the browser once the person
// has confirmed or dismissed. concierge (`runner/src/web/authorize.rs`, `confirm_url`)
// builds `return_to` as the authorize request rebuilt, so that route is the only target
// accepted: the page runs on the platform origin with a signed-in session, and an open
// redirect there would hand a phishing link the platform's address bar.
//
// The string is checked as text first, because the URL parser forgives what it should not
// be asked to: it drops tabs and newlines inside a path (`/\t/evil` becomes `//evil`) and
// reads `\` as `/`. The parsed result is then checked as well, so the two readings agree.

/** The authorize route's public path and the start of every accepted `return_to`. */
export const AUTHORIZE_PATH = "/api/auth/authorize";
const PREFIX = `${AUTHORIZE_PATH}?`;
// C0 controls, DEL and the C1 range: none of them occurs in a URL concierge writes.
// eslint-disable-next-line no-control-regex -- matching control characters is the point of this check
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
// concierge answers a longer id as unknown without a lookup (`MAX_CLIENT_ID_LEN`).
const MAX_CLIENT_ID_LEN = 64;

export interface AuthorizeReturn {
  /** `return_to` exactly as concierge wrote it. */
  href: string;
  /** The client the authorize request is for; the only source of the app's name on the page. */
  clientId: string;
}

/**
 * The accepted `return_to`, or null. It must be a relative path to the authorize route on
 * `origin` with no scheme, no `//` or `/\` at the start, no backslash, fragment or control
 * character anywhere, and it must name one `client_id`. Concierge never writes a fragment;
 * one would ride authorize's 302 onto the client's `redirect_uri`.
 */
export function authorizeReturnTo(raw: string | null, origin: string): AuthorizeReturn | null {
  if (!raw || !raw.startsWith(PREFIX)) return null;
  if (raw.includes("\\") || raw.includes("#") || CONTROL.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw, origin);
  } catch {
    return null;
  }
  if (url.origin !== origin || url.pathname !== AUTHORIZE_PATH) return null;
  const ids = url.searchParams.getAll("client_id");
  const clientId = ids[0];
  if (ids.length !== 1 || !clientId || clientId.length > MAX_CLIENT_ID_LEN) return null;
  return { href: raw, clientId };
}
