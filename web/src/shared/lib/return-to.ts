// Where an OAuth round trip (Google, GitHub) lands back. It is a top-level navigation to the
// platform's /api/auth/login, so the target must say which host to come back to.
//
// `data-return-to` arrives as a root-relative path on the host or an absolute URL on it
// (the two wrappers that exist disagree); both are turned into an absolute URL on THIS
// page's origin, and anything pointing elsewhere is dropped for the current page. The
// current page is taken without its query and hash: they may carry one-time tokens or an
// `auth_error`, and the URL travels through the platform's logs and the provider. The
// plane re-checks the origin against the scope allowlist; on the platform itself the path
// alone is sent, which is all it accepts there today.

import { safeHref } from "@evinvest/mfe";

export function returnUrl(raw: string | null): URL {
  const here = new URL(location.origin + location.pathname);
  const href = safeHref(raw);
  if (!href) return here;
  const target = new URL(href, location.href);
  return target.origin === location.origin ? target : here;
}

/** The platform's OAuth login; no `provider` leaves the choice to the plane's default. */
export function loginHref(origin: string, provider: string | null, returnTo: string | null): string {
  const target = returnUrl(returnTo);
  const back = target.origin === origin ? target.pathname + target.search + target.hash : target.href;
  const query = new URLSearchParams(provider ? { provider, returnTo: back } : { returnTo: back });
  return `${origin}/api/auth/login?${query.toString()}`;
}
