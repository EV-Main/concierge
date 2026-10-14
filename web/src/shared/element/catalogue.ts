import type { Locale, Messages } from "@evinvest/i18n";
import raw from "virtual:mfe/messages";

import { isRecord } from "../lib/guard";

// Each bundle carries only the keys its own modules render (scripts/build.mjs): an element
// is injected into hosts' pages, and the whole catalogue in five languages would outweigh
// the element itself. English needs no catalogue — it is written at the call site.

function parse(value: unknown): Partial<Record<Locale, Messages>> {
  if (!isRecord(value)) return {};
  const out: Partial<Record<Locale, Messages>> = {};
  for (const [locale, messages] of Object.entries(value)) {
    if (!isRecord(messages)) continue;
    const strings = Object.entries(messages).filter((entry): entry is [string, string] => typeof entry[1] === "string");
    // The keys are the build's own locale list, all of them `Locale`s.
    out[locale as Locale] = Object.fromEntries(strings);
  }
  return out;
}

const CATALOGUES = parse(raw);

export function messagesFor(locale: Locale): Messages {
  return CATALOGUES[locale] ?? {};
}
