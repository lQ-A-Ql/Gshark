export type EvidenceModule =
  | "apt"
  | "c2"
  | "hunting"
  | "industrial"
  | "object"
  | "vehicle"
  | "usb"
  | "media"
  | "misc"
  | "stream"
  | "unknown";

export type EvidenceSeverity = "critical" | "high" | "medium" | "low" | "info";

export type EvidenceConfidenceLabel = "high" | "medium" | "low" | "unknown";

export type EvidenceMetadataValue = string | number | boolean | null | string[] | number[] | boolean[];

export type EvidenceMetadata = Record<string, EvidenceMetadataValue>;

export interface UnifiedEvidenceRecord {
  id: string;
  module: EvidenceModule;
  sourceModule?: string;
  packetId?: number;
  streamId?: number;
  family?: string;
  feature?: string;
  entityType?: string;
  protocol?: string;
  version?: string;
  displayName?: string;
  ruleId?: string;
  ruleName?: string;
  playbookId?: string;
  playbookName?: string;
  iocType?: string;
  iocValue?: string;
  ja3Hash?: string;
  ja3sHash?: string;
  metadata?: EvidenceMetadata;
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
