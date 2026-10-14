// The one place the build reads its environment. Everything a bundle needs at runtime
// is inlined as `__EV_BUILD__` and parsed again by src/shared/config/build.ts, so a typo
// in a variable name fails here, at build time, rather than as a dead button in a host.

function origin(name, fallback) {
  const raw = process.env[name] ?? fallback;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name}: not a URL: ${raw}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`${name}: not http(s): ${raw}`);
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
  turnstileSiteKey: optional("EV_TURNSTILE_SITEKEY"),
  // The chip's Services entry; unset, it is left out (as NEXT_PUBLIC_SA_PANEL_URL in the cabinet).
  saPanelUrl: optional("EV_SA_PANEL_URL"),
  // Where hosts load dist/ from: concierge serves it at /auth/mfe/*, reached through the
  // conductor's existing `/api/auth/:path*` rewrite. The registry's scriptUrls are written
  // root-relative under it, so they resolve against the registry's own URL.
  basePath: basePath("EV_MFE_BASE_PATH", "/api/auth/mfe/"),
};
