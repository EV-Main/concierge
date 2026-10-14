import { BUILD } from "./build";

/**
 * Overrides the identity plane's origin for one element — honoured only by a dev or stand
 * build (`EV_ALLOW_ORIGIN_OVERRIDE`). In production any script on a host page could set it
 * and aim the element's credentialed calls, and the bundles it loads, at another server.
 */
export const ORIGIN_ATTR = "data-origin";

/** A bare http(s) origin, or null. */
function originOf(raw: string | null): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.origin === raw.replace(/\/$/, "") ? url.origin : null;
  } catch {
    return null;
  }
}

/** The identity plane this element talks to: the built-in one, or `data-origin` in a dev build. */
export function apiOriginOf(element: Element): string {
  if (!BUILD.allowOriginOverride) return BUILD.publicOrigin;
  return originOf(element.getAttribute(ORIGIN_ATTR)) ?? BUILD.publicOrigin;
}

/**
 * Whether this page may act on the open session. Everything that changes a signed-in
 * account (password, passkeys, sessions, username, sign-out) is accepted by the plane
 * only from its own origin (ORG-RESTRUCTURE-PLAN §3.9 F), and its CSRF cookie is
 * readable only there; a host on a scope's subdomain links to the platform instead.
 */
export function isPlatformPage(origin: string): boolean {
  return typeof location !== "undefined" && location.origin === origin;
}

export type AccountSection = "profile" | "security" | "notifications";

/** The platform's own account page, where a scope host sends every account action. */
export function platformAccountUrl(origin: string, section?: AccountSection): string {
  return `${origin}/admin/account${section ? `?section=${section}` : ""}`;
}

/**
 * The platform's sign-out confirmation, coming back to this page without its query or hash
 * (those may carry tokens). A scope host's own sign-out ends only its RP session; this ends
 * the platform session behind it, which the host cannot do cross-origin (§3.9 F).
 */
export function platformLogoutUrl(origin: string): string {
  const back = location.origin + location.pathname;
  return `${origin}/api/auth/logout/confirm?return_to=${encodeURIComponent(back)}`;
}
