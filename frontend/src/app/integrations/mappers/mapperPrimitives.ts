import type { AnalysisConversation, TrafficBucket } from "../../core/types";

export function asBucket(input: any): TrafficBucket {
  return {
    label: String(input.label ?? ""),
    count: Number(input.count ?? 0),
  };
}

export function asConversation(input: any): AnalysisConversation {
  return {
    label: String(input.label ?? ""),
    protocol: String(input.protocol ?? "") || undefined,
    count: Number(input.count ?? 0),
  };
}

export function asStringList(input: unknown): string[] {
  return Array.isArray(input) ? input.map((value) => String(value ?? "")) : [];
}

export function asPositiveNumbers(input: unknown): number[] {
  if (!Array.isArray(input)) return [];
  return input.map((value) => Number(value ?? 0)).filter(Boolean);
}

export function asPositiveFiniteNumbers(input: unknown): number[] {
  if (!Array.isArray(input)) return [];
  return input.map((value) => Number(value ?? 0)).filter((value) => Number.isFinite(value) && value > 0);
}

export function asPlainObject(input: unknown): Record<string, unknown> | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return undefined;
  }
  return input as Record<string, unknown>;
}
