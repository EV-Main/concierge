/** What a page asks the step-up element to confirm, as its attributes carry it. */
export interface StepupRequest {
  intentHash: string;
  minAal: number;
}

const INTENT_HASH = /^[0-9a-f]{64}$/;
const LEVEL = /^\d{1,3}$/;
const MAX_LEVEL = 255; // the plane reads `min_aal` as a u8

/** Null when either is missing or malformed: there is no default assurance to fall back to. */
export function parseStepupRequest(intentHash: string | null, minAal: string | null): StepupRequest | null {
  if (intentHash === null || minAal === null || !INTENT_HASH.test(intentHash) || !LEVEL.test(minAal)) return null;
  const level = Number(minAal);
  return level <= MAX_LEVEL ? { intentHash, minAal: level } : null;
}
