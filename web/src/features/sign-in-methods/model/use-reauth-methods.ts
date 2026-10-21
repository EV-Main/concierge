import { useEffect, useState } from "react";

import type { AuthApi, AuthError } from "../../../shared/api/auth-api";
import { passkeysSupported } from "../../../shared/lib/webauthn";
import { readMethods } from "../api/methods-api";
import { reauthMethods, type ReauthMethod } from "./reauth";

export type ReauthChoice = { kind: "loading" } | { kind: "ready"; methods: ReauthMethod[] } | { kind: "failed"; error: AuthError };

/**
 * The ways the signed-in account can confirm, read from `/methods` once per mount. The
 * Security tab already holds those facts; a dialog opened by a host has to ask for them.
 */
export function useReauthMethods(api: AuthApi): ReauthChoice {
  const [choice, setChoice] = useState<ReauthChoice>({ kind: "loading" });
  useEffect(() => {
    let live = true;
    void readMethods(api).then((answer) => {
      if (!live) return;
      if (!answer.ok) return setChoice({ kind: "failed", error: answer.error });
      const { emailVerified, password, passkeys } = answer.body;
      setChoice({ kind: "ready", methods: reauthMethods({ emailVerified, password, passkeys: passkeys.length }, passkeysSupported()) });
    });
    return () => {
      live = false;
    };
  }, [api]);
  return choice;
}
