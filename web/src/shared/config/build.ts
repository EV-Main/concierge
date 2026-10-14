import { bool, isRecord, optionalStr, str } from "../lib/guard";

export interface BuildConfig {
  /** The identity plane's origin — where /api/auth/* answers and the only one that may act on a session. */
  publicOrigin: string;
  /** A dev or stand build: `data-origin` is honoured and the bare `ev_csrf` cookie is read. */
  allowOriginOverride: boolean;
  turnstileSiteKey: string | null;
  /** The chip's Services entry; null leaves it out. */
  saPanelUrl: string | null;
  /** Root-relative path of the published registry, beside the bundles. */
  registryPath: string;
}

function parse(raw: unknown): BuildConfig {
  if (!isRecord(raw)) throw new Error("__EV_BUILD__ is not an object");
  const publicOrigin = str(raw, "publicOrigin");
  const allowOriginOverride = bool(raw, "allowOriginOverride");
  const registryPath = str(raw, "registryPath");
  const turnstileSiteKey = optionalStr(raw, "turnstileSiteKey");
  const saPanelUrl = optionalStr(raw, "saPanelUrl");
  if (!publicOrigin || allowOriginOverride === null || !registryPath || turnstileSiteKey === undefined || saPanelUrl === undefined) {
    throw new Error("__EV_BUILD__ is malformed; rebuild with scripts/build.mjs");
  }
  return { publicOrigin, allowOriginOverride, turnstileSiteKey, saPanelUrl, registryPath };
}

export const BUILD: BuildConfig = parse(__EV_BUILD__);
