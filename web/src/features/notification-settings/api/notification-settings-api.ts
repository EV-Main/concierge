// Delivery preferences (concierge runner/src/web/account.rs). Platform origin only, the
// writes CSRF-checked. A plane without the routes answers 404, which the section shows as
// "not available yet" rather than as a failure.

import type { AuthApi } from "../../../shared/api/auth-api";
import { bool, isRecord, listOf, str } from "../../../shared/lib/guard";

export interface TopicSubscription {
  topic: string;
  /** Server-owned copy, rendered verbatim. */
  label: string;
  description: string;
  subscribed: boolean;
  emailEnabled: boolean;
}

/** Both master channels may be off at once: "stop contacting me" is a supported state. */
export interface NotificationSettings {
  inAppEnabled: boolean;
  emailEnabled: boolean;
  email: string;
  emailVerified: boolean;
  topics: TopicSubscription[];
}

function parseTopic(raw: unknown): TopicSubscription | null {
  if (!isRecord(raw)) return null;
  const topic = str(raw, "topic");
  const label = str(raw, "label");
  const description = str(raw, "description");
  const subscribed = bool(raw, "subscribed");
  const emailEnabled = bool(raw, "email_enabled");
  if (topic === null || label === null || description === null || subscribed === null || emailEnabled === null) return null;
  return { topic, label, description, subscribed, emailEnabled };
}

function parseSettings(raw: unknown): NotificationSettings | null {
  if (!isRecord(raw)) return null;
  const inAppEnabled = bool(raw, "in_app_enabled");
  const emailEnabled = bool(raw, "email_enabled");
  const email = str(raw, "email");
  const emailVerified = bool(raw, "email_verified");
  const topics = listOf(raw["topics"], parseTopic);
  if (inAppEnabled === null || emailEnabled === null || email === null || emailVerified === null || !topics) return null;
  return { inAppEnabled, emailEnabled, email, emailVerified, topics };
}

export const readSettings = (api: AuthApi) => api.get("/notifications/settings", parseSettings);

/** Every write answers with the whole new snapshot, which replaces the old one. */
export const setChannel = (api: AuthApi, channel: "in_app" | "email", enabled: boolean) => api.send("POST", "/notifications/settings/channel", { channel, enabled }, parseSettings, true);

export const setTopic = (api: AuthApi, topic: string, subscribed: boolean, emailEnabled: boolean) =>
  api.send("POST", "/notifications/settings/topic", { topic, subscribed, email_enabled: emailEnabled }, parseSettings, true);
