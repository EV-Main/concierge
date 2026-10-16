import { useCallback, useEffect, useState } from "react";

import type { AuthApi } from "../api/auth-api";
import { readSession, type SessionState } from "../api/session";

/** The platform session, read once on mount; `refresh` re-reads it after an action changed it. */
export function useSession(api: AuthApi): { session: SessionState; refresh: () => Promise<void> } {
  const [session, setSession] = useState<SessionState>({ kind: "loading" });

  useEffect(() => {
    let live = true;
    void readSession(api).then((next) => {
      if (live) setSession(next);
    });
    return () => {
      live = false;
    };
  }, [api]);

  const refresh = useCallback(async () => setSession(await readSession(api)), [api]);
  return { session, refresh };
}
