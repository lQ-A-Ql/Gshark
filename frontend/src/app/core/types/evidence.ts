export type EvidenceModule =
  | "apt"
  | "c2"
  | "hunting"
  | "industrial"
  | "object"
  | "vehicle"
  | "usb"
  | "misc"
  | "stream"
  | "unknown";

export type EvidenceSeverity = "critical" | "high" | "medium" | "low" | "info";

export type EvidenceConfidenceLabel = "high" | "medium" | "low" | "unknown";

export interface UnifiedEvidenceRecord {
  id: string;
  module: EvidenceModule;
  sourceModule?: string;
  packetId?: number;
  streamId?: number;
  family?: string;
  actorId?: string;
  actorName?: string;
  sourceType: string;
  summary: string;
  value?: string;
  confidence?: number;
  confidenceLabel: EvidenceConfidenceLabel;
  severity: EvidenceSeverity;
  source?: string;
  destination?: string;
  host?: string;
  uri?: string;
  tags: string[];
  caveats: string[];
}

export function confidenceLabel(confidence?: number): EvidenceConfidenceLabel {
  if (confidence === undefined || Number.isNaN(confidence)) return "unknown";
  if (confidence >= 75) return "high";
  if (confidence >= 45) return "medium";
  if (confidence > 0) return "low";
  return "unknown";
}

export function confidenceLabelText(label: EvidenceConfidenceLabel) {
  return {
    high: "高置信",
    medium: "中置信",
    low: "低置信",
    unknown: "待评估",
  }[label];
}

export function evidenceSeverityFromConfidence(confidence?: number): EvidenceSeverity {
  if (confidence === undefined || confidence <= 0) return "info";
  if (confidence >= 85) return "critical";
  if (confidence >= 70) return "high";
  if (confidence >= 45) return "medium";
  return "low";
}
