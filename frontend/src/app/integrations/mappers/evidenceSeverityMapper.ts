import type { EvidenceSeverity } from "../../core/types";

const VALID_SEVERITIES = new Set<string>(["critical", "high", "medium", "low", "info"]);

export function asEvidenceSeverity(raw: unknown): EvidenceSeverity {
  const s = String(raw ?? "info").toLowerCase();
  return VALID_SEVERITIES.has(s) ? (s as EvidenceSeverity) : "info";
}
