// A second factor proved for ONE operation of the money plane (runner/src/web/stepup.rs,
// docs/STEPUP-PROOF.md): the page's `intent_hash` and least assurance in, an opaque proof
// out. Answered for the platform and the listed host origins alike, by CORS and
// `Sec-Fetch-Site`, so there is no CSRF header: a host cannot read the `__Host-` CSRF cookie.

import type { AuthApi } from "../../../shared/api/auth-api";
import type { StepupProofDetail } from "../../../shared/element/events";
import { isRecord, str } from "../../../shared/lib/guard";
import { factorCeremonyAt } from "./second-factor-api";

function parseProof(raw: unknown): StepupProofDetail | null {
  if (!isRecord(raw)) return null;
  const proof = str(raw, "proof");
  const expiresAt = raw["expires_at"];
  return proof !== null && typeof expiresAt === "number" ? { proof, expiresAt } : null;
}

export const stepupOptions = (api: AuthApi, intentHash: string, minAal: number) => api.send("POST", "/stepup/options", { intent_hash: intentHash, min_aal: minAal }, factorCeremonyAt("ceremony_id"));

export const stepupVerify = (api: AuthApi, ceremony: string, factor: string, response: unknown) => api.send("POST", "/stepup/verify", { ceremony_id: ceremony, factor, response }, parseProof);
