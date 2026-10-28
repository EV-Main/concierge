import { useT } from "@evinvest/i18n/react";
import { Button, Checkbox, Label } from "@evinvest/uikit";
import { useEffect, useId, useRef, useState } from "react";

import { CopyButton } from "./copy-button";

function download(text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "evinvest-recovery-codes.txt";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url)); // Safari drops a download whose URL is revoked in the same task as the click.
}

/** The plane shows a set once and keeps only digests, so the panel stays until the reader says they saved it. */
export function RecoveryCodes({ codes, onSaved }: { codes: string[]; onSaved: () => void }) {
  const t = useT();
  const [saved, setSaved] = useState(false);
  const titleId = useId();
  const checkId = useId();
  const panel = useRef<HTMLElement>(null);
  const text = codes.join("\n");

  useEffect(() => {
    panel.current?.focus();
  }, []);

  return (
    <section ref={panel} tabIndex={-1} aria-labelledby={titleId} className="flex flex-col gap-3 outline-none">
      <div className="flex flex-col gap-1">
        <h3 id={titleId} className="m-0 text-sm font-semibold">
          {t("auth.secondFactor.codes.title", "Your recovery codes")}
        </h3>
        <p className="m-0 text-xs text-ink-soft">
          {t("auth.secondFactor.codes.sub", "Each one works once, in place of your authenticator. Keep them somewhere safe: we cannot show them again.")}
        </p>
      </div>
      <ul className="m-0 grid list-none grid-cols-2 gap-x-6 gap-y-1 p-0 font-mono text-sm text-ink">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-3">
        <CopyButton text={text} label={t("auth.secondFactor.codes.copy", "Copy codes")} />
        <Button type="button" variant="outline" size="sm" onClick={() => download(text)}>
          {t("auth.secondFactor.codes.download", "Download .txt")}
        </Button>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox id={checkId} checked={saved} onCheckedChange={setSaved} />
        <Label htmlFor={checkId} className="text-sm">
          {t("auth.secondFactor.codes.saved", "I saved my recovery codes")}
        </Label>
      </div>
      <Button size="sm" className="self-start" disabled={!saved} onClick={onSaved}>
        {t("auth.secondFactor.codes.done", "Done")}
      </Button>
    </section>
  );
}
