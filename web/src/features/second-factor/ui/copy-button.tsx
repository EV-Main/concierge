import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useState } from "react";

export function CopyButton({ text, label }: { text: string; label: string }) {
  const t = useT();
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      // A denied clipboard leaves the text on screen to select by hand; the status says so.
      setState("failed");
    }
  }

  return (
    <span className="flex items-center gap-2">
      <Button type="button" variant="outline" size="sm" onClick={() => void copy()}>
        {label}
      </Button>
      <span role="status" className="text-xs text-ink-soft">
        {state === "copied" && t("auth.secondFactor.copied", "Copied")}
        {state === "failed" && t("auth.secondFactor.copyFailed", "Could not copy. Select the text instead.")}
      </span>
    </span>
  );
}
