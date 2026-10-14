// Shape checks for JSON from the identity plane. Every body is read as `unknown` and
// narrowed here; a field of the wrong type makes the whole answer unreadable rather
// than half-rendered.

export type Json = Record<string, unknown>;

export function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function str(source: Json, key: string): string | null {
  const value = source[key];
  return typeof value === "string" ? value : null;
}

export function bool(source: Json, key: string): boolean | null {
  const value = source[key];
  return typeof value === "boolean" ? value : null;
}

/** `null` when absent or null; `undefined` when present with another type — a malformed body. */
export function optionalStr(source: Json, key: string): string | null | undefined {
  const value = source[key];
  if (value === undefined || value === null) return null;
  return typeof value === "string" ? value : undefined;
}

/** Every element parsed, or null when any one does not. */
export function listOf<T>(value: unknown, parse: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) return null;
  const out: T[] = [];
  for (const item of value) {
    const parsed = parse(item);
    if (parsed === null) return null;
    out.push(parsed);
  }
  return out;
}
