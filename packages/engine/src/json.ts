/**
 * Reading JSON that other programs own: the CLI's reports and the GitHub event payload.
 *
 * Their shapes are those programs' contracts, so they are read defensively, field by field, as
 * unknown values narrowed at each step, rather than typed here.
 */

export type JsonObject = Record<string, unknown>;

/** Whether value is a plain object. */
export function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** value when it is a plain object, else an empty one. */
export function obj(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

/** value when it is an array, else an empty one. */
export function arr(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** The value at a path of object keys, or undefined when any step is missing. */
export function at(value: unknown, ...keys: string[]): unknown {
  let current: unknown = value;
  for (const key of keys) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return undefined;
    current = (current as JsonObject)[key];
  }
  return current;
}

/** value as a string, or fallback when it is missing; numbers are written out. */
export function text(value: unknown, fallback = ''): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return fallback;
}
