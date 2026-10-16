import { useT } from "@evinvest/i18n/react";
import { useEffect, useState } from "react";

import { useElement } from "../../../shared/element/element-context";
import { listSessions, revokeSession, type Session } from "../api/sessions-api";

/** The session list and the two ways to shorten it; a revoke re-reads the list. */
export function useSessions() {
  const t = useT();
  const { api } = useElement();
  const [sessions, setSessions] = useState<Session[] | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Bumped after a revoke, which re-reads the list.
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let live = true;
    void listSessions(api).then((answer) => {
      if (live) setSessions(answer.ok ? answer.body : null);
    });
    return () => {
      live = false;
    };
  }, [api, revision]);

  async function revokeAll(ids: string[]) {
    setBusy(true);
    setError(null);
    for (const id of ids) {
      const answer = await revokeSession(api, id);
      if (!answer.ok) {
        setError(t("settings.revokeFailed", "That session could not be signed out. Try again."));
        break;
      }
    }
    setRevision((r) => r + 1);
    setBusy(false);
  }

  return {
    sessions,
    error,
    busy,
    revoke: (id: string) => revokeAll([id]),
    revokeOthers: () => revokeAll((sessions ?? []).filter((s) => !s.current).map((s) => s.id)),
  };
}
