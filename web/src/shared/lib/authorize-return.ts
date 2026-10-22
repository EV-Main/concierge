// Where the platform confirmation page (`reauth.html`) sends the browser once the person
// has confirmed or dismissed. concierge (`runner/src/web/authorize.rs`, `confirm_url`)
// builds `return_to` as a path back to its own authorize route, so that route is the only
// target accepted: the page runs on the platform origin with a signed-in session, and an
// open redirect there would hand a phishing link the platform's address bar.
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

/**
 * `raw` if it is a relative path to the authorize route on `origin`, or null. No scheme,
 * no `//` or `/\` at the start, no backslash and no control character anywhere.
 */
export function authorizeReturnTo(raw: string | null, origin: string): string | null {
  if (!raw || !raw.startsWith(PREFIX)) return null;
  if (raw.includes("\\") || CONTROL.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw, origin);
  } catch {
    return null;
  }
  return url.origin === origin && url.pathname === AUTHORIZE_PATH ? raw : null;
}
