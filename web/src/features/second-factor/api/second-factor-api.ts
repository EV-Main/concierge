// The account's second factor (runner/src/web/second_factor.rs). Platform pages only and
// CSRF-checked, like every route that acts on a session. Changing factors on an account that
// has one asks the session to have proved one within five minutes (`second_factor_required`).

import { anyBody, type AuthApi } from "../../../shared/api/auth-api";
import { isRecord, listOf, optionalStr, str, type Json } from "../../../shared/lib/guard";

export interface Factor {
  id: string;
  kind: string;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface SecondFactors {
  factors: Factor[];
  recoveryCodesLeft: number;
}

export interface Offer {
  enrolment: string;
  kind: string;
  uri: string;
  secret: string;
}

export interface FactorChallenge {
  id: string;
  kind: string;
  label: string | null;
  challenge: unknown;
}

export interface VerifyCeremony {
  ceremony: string;
  factors: FactorChallenge[];
}

function num(source: Json, key: string): number | null {
  const value = source[key];
  return typeof value === "number" ? value : null;
}

function parseFactor(raw: unknown): Factor | null {
  if (!isRecord(raw)) return null;
  const id = str(raw, "id");
  const kind = str(raw, "kind");
  const label = str(raw, "label");
  const createdAt = num(raw, "createdAt");
  const used = raw["lastUsedAt"];
  const lastUsedAt = used === null ? null : typeof used === "number" ? used : undefined;
  if (id === null || kind === null || label === null || createdAt === null || lastUsedAt === undefined) return null;
  return { id, kind, label, createdAt, lastUsedAt };
}

/** `secondFactor: null` is a plane without the feature, which the card renders as nothing. */
function parseSummary(raw: unknown): { secondFactor: SecondFactors | null } | null {
  if (!isRecord(raw)) return null;
  const sf = raw["secondFactor"];
  if (sf === null) return { secondFactor: null };
  if (!isRecord(sf)) return null;
  const factors = listOf(sf["factors"], parseFactor);
  const recoveryCodesLeft = num(sf, "recoveryCodesLeft");
  return factors && recoveryCodesLeft !== null ? { secondFactor: { factors, recoveryCodesLeft } } : null;
}

function parseOffer(raw: unknown): Offer | null {
  if (!isRecord(raw) || !isRecord(raw["offer"])) return null;
  const enrolment = str(raw, "enrolment");
  const kind = str(raw, "kind");
  const uri = str(raw["offer"], "uri");
  const secret = str(raw["offer"], "secret");
  return enrolment !== null && kind !== null && uri !== null && secret !== null ? { enrolment, kind, uri, secret } : null;
}

function parseCodes(raw: unknown): string[] | null {
  return isRecord(raw) ? listOf(raw["recoveryCodes"], (c) => (typeof c === "string" ? c : null)) : null;
}

/** `codes: null` after a factor that is not the account's first: its codes were shown before. */
function parseConfirmed(raw: unknown): { codes: string[] | null } | null {
  if (!isRecord(raw)) return null;
  if (raw["recoveryCodes"] === null) return { codes: null };
  const codes = parseCodes(raw);
  return codes ? { codes } : null;
}

function parseChallenge(raw: unknown): FactorChallenge | null {
  if (!isRecord(raw)) return null;
  const id = str(raw, "id");
  const kind = str(raw, "kind");
  const label = optionalStr(raw, "label");
  return id !== null && kind !== null && label !== undefined ? { id, kind, label, challenge: raw["challenge"] } : null;
}

function parseVerifyCeremony(raw: unknown): VerifyCeremony | null {
  if (!isRecord(raw)) return null;
  const ceremony = str(raw, "ceremony");
  const factors = listOf(raw["factors"], parseChallenge);
  return ceremony !== null && factors ? { ceremony, factors } : null;
}

export const readSecondFactors = (api: AuthApi) => api.get("/methods", parseSummary);

export const startEnrolment = (api: AuthApi, label: string) => api.send("POST", "/second-factor/enrol/start", { kind: "totp", label }, parseOffer, true);

export const confirmEnrolment = (api: AuthApi, enrolment: string, response: unknown) => api.send("POST", "/second-factor/enrol/confirm", { enrolment, response }, parseConfirmed, true);

export const verifyOptions = (api: AuthApi) => api.send("POST", "/second-factor/verify/options", {}, parseVerifyCeremony, true);

export const verifyFactor = (api: AuthApi, ceremony: string, factor: string, response: unknown) => api.send("POST", "/second-factor/verify", { ceremony, factor, response }, anyBody, true);

export const removeFactor = (api: AuthApi, factor: string) => api.send("POST", "/second-factor/remove", { factor }, anyBody, true);

export const replaceRecoveryCodes = (api: AuthApi) => api.send("POST", "/second-factor/recovery-codes", {}, parseCodes, true);

/** Spends a recovery code: every factor and code goes, and every session of the account ends. */
export const recover = (api: AuthApi, code: string) => api.send("POST", "/second-factor/recover", { code }, anyBody, true);
