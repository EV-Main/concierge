import { useLocale, useT } from "@evinvest/i18n/react";
import { Button, ListRow } from "@evinvest/uikit";

import { useElement } from "../../../shared/element/element-context";
import { passkeysSupported } from "../../../shared/lib/webauthn";
import { addPasskey, removePasskey, type SignInMethods } from "../api/methods-api";
import { reauthMethods } from "../model/reauth";
import { useReauthGate } from "../model/use-reauth-gate";
import { ReauthMethods } from "./reauth-methods";
import { ReauthReady } from "./reauth-ready";
import { ReauthStep } from "./reauth-step";
import { refusal } from "./refusal";

export function Passkeys({ methods, onChanged }: { methods: SignInMethods; onChanged: () => void }) {
  const t = useT();
  const locale = useLocale();
  const { api } = useElement();
  const gate = useReauthGate(onChanged);
  const locked = gate.busy || gate.stage !== "idle";

  const name = () => `${t("auth.passkeys.default", "Passkey")} · ${new Date().toLocaleDateString(locale)}`;
  const confirmWith = reauthMethods({ emailVerified: methods.emailVerified, password: methods.password, passkeys: methods.passkeys.length }, passkeysSupported());
  return (
    <>
      <ListRow label={t("auth.passkeys.title", "Passkeys")} description={t("auth.passkeys.sub", "Sign in with your fingerprint, face or screen lock — no code, no password")}>
        {passkeysSupported() && (
          <Button variant="outline" size="sm" disabled={locked} onClick={() => void gate.start({ run: () => addPasskey(api, name()), gesture: true })}>
            {t("auth.passkeys.add", "Add a passkey")}
          </Button>
        )}
      </ListRow>
      {methods.passkeys.map((passkey) => (
        <ListRow key={passkey.id} label={passkey.name}>
          <Button variant="outline" size="sm" disabled={locked} onClick={() => void gate.start({ run: () => removePasskey(api, passkey.id), gesture: false })}>
            {t("auth.passkeys.remove", "Remove")}
          </Button>
        </ListRow>
      ))}
      {gate.stage === "confirm" && (
        <ReauthStep sub={t("auth.reauth.sub", "You signed in a while ago. Confirm again to change your passkeys.")} onCancel={gate.cancel}>
          <ReauthMethods methods={confirmWith} onConfirmed={gate.confirmed} />
        </ReauthStep>
      )}
      {gate.stage === "ready" && <ReauthReady busy={gate.busy} onProceed={gate.proceed} onCancel={gate.cancel} />}
      {gate.error && (
        <li role="alert" className="list-none py-3 text-xs text-accent-error">
          {refusal(t, gate.error)}
        </li>
      )}
    </>
  );
}
