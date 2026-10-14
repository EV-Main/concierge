// Where an OAuth round trip (Google, GitHub) lands back. It is a top-level navigation to the
// platform's /api/auth/login, so the target must say which host to come back to.
//
// `data-return-to` arrives as a root-relative path on the host or an absolute URL on it
// (the two wrappers that exist disagree); both are turned into an absolute URL on THIS
// page's origin, and anything pointing elsewhere is dropped for the current page. The
// plane re-checks the origin against the scope allowlist; on the platform itself the
// path alone is sent, which is all it accepts there today.

import { safeHref } from "@evinvest/mfe";

export function returnUrl(raw: string | null): URL {
  const here = new URL(location.href);
  here.searchParams.delete("auth_error");
  const href = safeHref(raw);
  if (!href) return here;
  const target = new URL(href, location.href);
  return target.origin === location.origin ? target : here;
}

export function loginHref(origin: string, provider: string, returnTo: string | null): string {
  const target = returnUrl(returnTo);
  const back = target.origin === origin ? target.pathname + target.search + target.hash : target.href;
  return `${origin}/api/auth/login?provider=${provider}&returnTo=${encodeURIComponent(back)}`;
}
