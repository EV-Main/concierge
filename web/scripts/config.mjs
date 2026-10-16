// The one place the build reads its environment. Everything a bundle needs at runtime
// is inlined as `__EV_BUILD__` and parsed again by src/shared/config/build.ts, so a typo
// in a variable name fails here, at build time, rather than as a dead button in a host.

function flag(name) {
  const raw = process.env[name]?.trim() ?? "";
  if (raw === "" || raw === "0" || raw === "false") return false;
  if (raw === "1" || raw === "true") return true;
  throw new Error(`${name}: expected 1/true or 0/false, got ${raw}`);
}

// A dev or stand build: elements honour `data-origin` and the platform may be plain http.
// Off in production, where a host page that sets `data-origin` must not be able to point
// the elements' credentialed requests and the registry fetch at another plane.
const allowOriginOverride = flag("EV_ALLOW_ORIGIN_OVERRIDE");

function origin(name, fallback) {
  const raw = process.env[name] ?? fallback;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name}: not a URL: ${raw}`);
  }
  if (url.protocol !== "https:" && !(allowOriginOverride && url.protocol === "http:")) {
    throw new Error(`${name}: must be https (http only with EV_ALLOW_ORIGIN_OVERRIDE=1): ${raw}`);
  }
  if (url.origin !== raw.replace(/\/$/, "")) throw new Error(`${name}: must be a bare origin, got ${raw}`);
  return url.origin;
}

function optional(name) {
  const raw = process.env[name]?.trim();
  return raw ? raw : null;
}

function basePath(name, fallback) {
  const raw = process.env[name] ?? fallback;
  if (!raw.startsWith("/") || !raw.endsWith("/") || raw.startsWith("//")) throw new Error(`${name}: must be a root-relative directory like /auth/mfe/, got ${raw}`);
  return raw;
}

export const config = {
  // Where the identity plane answers /api/auth/*, and the only origin allowed to act on
  // an open session (ORG-RESTRUCTURE-PLAN §3.9).
  publicOrigin: origin("EV_PUBLIC_ORIGIN", "https://evinvest.ltd"),
  allowOriginOverride,
  turnstileSiteKey: optional("EV_TURNSTILE_SITEKEY"),
  // The chip's Services entry; unset, it is left out (as NEXT_PUBLIC_SA_PANEL_URL in the cabinet).
  saPanelUrl: optional("EV_SA_PANEL_URL"),
  // Where hosts load dist/ from: concierge serves it at /auth/mfe/*, reached through the
  // conductor's existing `/api/auth/:path*` rewrite. The registry's scriptUrls are written
  // root-relative under it, so they resolve against the registry's own URL.
  basePath: basePath("EV_MFE_BASE_PATH", "/api/auth/mfe/"),
};
