import { useT } from "@evinvest/i18n/react";
import { Button, ListRow } from "@evinvest/uikit";
import { useState } from "react";

import type { AuthAnswer } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { passkeysSupported } from "../../../shared/lib/webauthn";
import { addPasskey, removePasskey, type SignInMethods } from "../api/methods-api";
import { refusal } from "./refusal";

export function Passkeys({ methods, onChanged }: { methods: SignInMethods; onChanged: () => void }) {
  const t = useT();
  const { api } = useElement();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function act(action: () => Promise<AuthAnswer<true>>) {
    setBusy(true);
    setError(null);
    const answer = await action();
    setBusy(false);
    if (answer.ok) onChanged();
    else setError(refusal(t, answer.error));
  }

  const name = () => `${t("auth.passkeys.default", "Passkey")} · ${new Date().toLocaleDateString()}`;
  return (
    <>
      <ListRow label={t("auth.passkeys.title", "Passkeys")} description={t("auth.passkeys.sub", "Sign in with your fingerprint, face or screen lock — no code, no password")}>
        {passkeysSupported() && (
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void act(() => addPasskey(api, name()))}>
            {t("auth.passkeys.add", "Add a passkey")}
          </Button>
        )}
      </ListRow>
      {methods.passkeys.map((passkey) => (
        <ListRow key={passkey.id} label={passkey.name}>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void act(() => removePasskey(api, passkey.id))}>
            {t("auth.passkeys.remove", "Remove")}
          </Button>
        </ListRow>
      ))}
      {error && (
        <li role="alert" className="list-none py-3 text-xs text-accent-error">
          {error}
        </li>
      )}
    </>
  );
}
