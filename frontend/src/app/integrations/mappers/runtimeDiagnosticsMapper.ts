import { asPlainObject } from "./mapperPrimitives";

export function asNumberRecord(input: unknown): Record<string, number> | undefined {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(payload)) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) out[key] = numeric;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

export function asStringRecord(input: unknown): Record<string, string> | undefined {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(payload)) {
    const text = String(value ?? "").trim();
    if (text) out[key] = text;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}
