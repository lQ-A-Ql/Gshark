import type { EvidenceMetadata, EvidenceMetadataValue } from "../../core/types";
import { asPlainObject } from "./mapperPrimitives";

export function asEvidenceMetadata(input: unknown): EvidenceMetadata | undefined {
  const raw = asPlainObject(input);
  if (!raw) return undefined;

  const metadata: EvidenceMetadata = {};
  for (const [key, value] of Object.entries(raw)) {
    const normalized = asEvidenceMetadataValue(value);
    if (normalized !== undefined) {
      metadata[key] = normalized;
    }
  }
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

function asEvidenceMetadataValue(value: unknown): EvidenceMetadataValue | undefined {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (!Array.isArray(value)) return undefined;

  const strings = value.filter((item): item is string => typeof item === "string");
  if (strings.length === value.length) return strings;
  const numbers = value.filter((item): item is number => typeof item === "number");
  if (numbers.length === value.length) return numbers;
  const booleans = value.filter((item): item is boolean => typeof item === "boolean");
  if (booleans.length === value.length) return booleans;
  return undefined;
}
