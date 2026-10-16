import { useT } from "@evinvest/i18n/react";
import { Button, Input } from "@evinvest/uikit";
import { useState, type FormEvent } from "react";

import { useElement } from "../../../shared/element/element-context";
import { setUsername } from "../api/methods-api";
import { refusal } from "./refusal";

const MIN_USERNAME = 3;

export function UsernameForm({ current, onDone }: { current: string; onDone: () => void }) {
  const t = useT();
  const { api } = useElement();
  // An address-shaped current value is the email standing in for a username; it does not prefill.
  const [value, setValue] = useState(current.includes("@") ? "" : current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const answer = await setUsername(api, value.trim());
    setBusy(false);
    if (answer.ok) onDone();
    else setError(refusal(t, answer.error));
  }

  return (
    <li className="list-none pb-3">
      <form className="flex flex-col gap-2" onSubmit={(e) => void save(e)}>
      <Input autoComplete="username" aria-label={t("auth.username.title", "Username")} value={value} onChange={(e) => setValue(e.target.value)} />
      <Button type="submit" size="sm" className="self-start" disabled={busy || value.trim().length < MIN_USERNAME}>
        {t("auth.username.save", "Save")}
      </Button>
        {error && <p role="alert" className="m-0 text-xs text-accent-error">{error}</p>}
      </form>
    </li>
  );
}
