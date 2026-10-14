import { useEffect, useState } from "react";

import type { SessionUser } from "../../../shared/api/session";
import { useElement } from "../../../shared/element/element-context";
import { readMe } from "../api/me-api";

/** What the profile card shows; the fields past the session's are known on the platform only. */
export interface Profile {
  email: string;
  emailVerified: boolean;
  username: string | null;
  preferredName: string | null;
  kycLevel: number | null;
  breakGlass: boolean;
}

function fromSession(user: SessionUser): Profile {
  return { email: user.email, emailVerified: user.emailVerified, username: user.username, preferredName: null, kycLevel: null, breakGlass: false };
}

/**
 * The platform reads `/me`; a scope host cannot, and shows the session's fields. A `/me`
 * that fails falls back to the session too — the card is never emptier than the chip.
 */
export function useProfile(user: SessionUser): Profile | null {
  const { api, platform } = useElement();
  const [me, setMe] = useState<Profile | null>(null);
  const [settled, setSettled] = useState(!platform);

  useEffect(() => {
    if (!platform) return;
    let live = true;
    void readMe(api).then((answer) => {
      if (!live) return;
      if (answer.ok) setMe(answer.body);
      setSettled(true);
    });
    return () => {
      live = false;
    };
  }, [api, platform]);

  if (!settled) return null;
  return me ?? fromSession(user);
}
