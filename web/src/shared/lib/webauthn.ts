// The identity plane speaks WebAuthn as JSON with base64url binaries (webauthn-rs); the
// browser API wants ArrayBuffers. These convert at the edge, both ways, and nothing else.

import { isRecord, str, type Json } from "./guard";

function toBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)).buffer;
}

function toBase64url(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A credential list with its base64url ids decoded; null when an entry has no id. */
function withIds(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.flatMap((entry: unknown) => {
    if (!isRecord(entry)) return [];
    const id = str(entry, "id");
    return id ? [{ type: "public-key" as const, id: toBuffer(id), ...(Array.isArray(entry["transports"]) ? { transports: entry["transports"].filter((t): t is AuthenticatorTransport => typeof t === "string") } : {}) }] : [];
  });
}

/** The `publicKey` record of a ceremony's options, or null when the plane sent something else. */
export function publicKeyOf(options: unknown): Json | null {
  return isRecord(options) && isRecord(options["publicKey"]) ? options["publicKey"] : null;
}

export function creationOptions(pk: Json): CredentialCreationOptions | null {
  const challenge = str(pk, "challenge");
  const rp = pk["rp"];
  const user = pk["user"];
  if (!challenge || !isRecord(rp) || !isRecord(user) || !Array.isArray(pk["pubKeyCredParams"])) return null;
  const userId = str(user, "id");
  const rpName = str(rp, "name");
  if (!userId || !rpName) return null;
  // The remaining members (timeout, attestation, authenticatorSelection, extensions) are
  // passed through as the plane wrote them; the browser validates the dictionary itself and
  // rejects the ceremony, which reads as a cancelled prompt, if one is malformed.
  const rest = pk as Partial<PublicKeyCredentialCreationOptions>;
  return {
    publicKey: {
      ...rest,
      rp: { ...rest.rp, name: rpName },
      challenge: toBuffer(challenge),
      user: { id: toBuffer(userId), name: str(user, "name") ?? "", displayName: str(user, "displayName") ?? "" },
      pubKeyCredParams: rest.pubKeyCredParams ?? [],
      excludeCredentials: withIds(pk["excludeCredentials"]) ?? [],
    },
  };
}

export function requestOptions(pk: Json): CredentialRequestOptions | null {
  const challenge = str(pk, "challenge");
  if (!challenge) return null;
  // As in creationOptions: everything but the binaries goes to the browser as written.
  const rest = pk as Partial<PublicKeyCredentialRequestOptions>;
  return { publicKey: { ...rest, challenge: toBuffer(challenge), allowCredentials: withIds(pk["allowCredentials"]) ?? [] } };
}

export function registrationJson(credential: PublicKeyCredential): Json | null {
  const response = credential.response;
  if (!(response instanceof AuthenticatorAttestationResponse)) return null;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: { attestationObject: toBase64url(response.attestationObject), clientDataJSON: toBase64url(response.clientDataJSON) },
    extensions: {},
  };
}

export function assertionJson(credential: PublicKeyCredential): Json | null {
  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) return null;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64url(response.authenticatorData),
      clientDataJSON: toBase64url(response.clientDataJSON),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle ? toBase64url(response.userHandle) : null,
    },
    extensions: {},
  };
}

/** The browser's prompt, or null when the reader dismissed it or it failed. */
export async function prompt(ask: () => Promise<Credential | null>): Promise<PublicKeyCredential | null> {
  try {
    const credential = await ask();
    return credential instanceof PublicKeyCredential ? credential : null;
  } catch {
    return null;
  }
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}
