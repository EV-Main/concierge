import { BUILD } from "./build";

/** Overrides the identity plane's origin for one element (a staging host, local dev). */
export const ORIGIN_ATTR = "data-origin";

/** A bare http(s) origin, or null. */
export function originOf(raw: string | null): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.origin === raw.replace(/\/$/, "") ? url.origin : null;
  } catch {
    return null;
  }
}

/** The identity plane this element talks to: its `data-origin`, else the built-in one. */
export function apiOriginOf(element: Element): string {
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
