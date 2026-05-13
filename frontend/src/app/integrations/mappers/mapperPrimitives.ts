import type { AnalysisConversation, TrafficBucket } from "../../core/types";

export function asBucket(input: unknown): TrafficBucket {
  const payload = asPlainObject(input);
  return {
    label: String(payload?.label ?? ""),
    count: Number(payload?.count ?? 0),
  };
}

export function asConversation(input: unknown): AnalysisConversation {
  const payload = asPlainObject(input);
  return {
    label: String(payload?.label ?? ""),
    protocol: String(payload?.protocol ?? "") || undefined,
    count: Number(payload?.count ?? 0),
  };
}

export const asArray = (input: unknown): unknown[] => (Array.isArray(input) ? input : []);

export function asStringList(input: unknown): string[] {
  return asArray(input).map((value) => String(value ?? ""));
}

export function asPositiveNumbers(input: unknown): number[] {
  return asArray(input)
    .map((value) => Number(value ?? 0))
    .filter(Boolean);
}

export function asPositiveFiniteNumbers(input: unknown): number[] {
  return asArray(input)
    .map((value) => Number(value ?? 0))
    .filter((value) => Number.isFinite(value) && value > 0);
}

export function asPlainObject(input: unknown): Record<string, unknown> | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }
  return input as Record<string, unknown>;
}

export const optionalString = (input: unknown): string | undefined => String(input ?? "") || undefined;

export const optionalNumber = (input: unknown): number | undefined => Number(input ?? 0) || undefined;
