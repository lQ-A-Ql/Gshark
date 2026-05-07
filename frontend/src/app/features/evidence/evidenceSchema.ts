import type { APTEvidenceRecord, C2IndicatorRecord, ThreatHit, ThreatLevel } from "../../core/types";

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

export function fromAPTEvidence(item: APTEvidenceRecord, index = 0): UnifiedEvidenceRecord {
  const tags = [
    item.sampleFamily,
    item.campaignStage,
    ...(item.transportTraits ?? []),
    ...(item.infrastructureHints ?? []),
    ...(item.ttpTags ?? []),
    ...(item.tags ?? []),
    ...(item.scoreFactors ?? []).map((factor) => `${factor.direction}:${factor.name}`),
  ].filter(Boolean) as string[];
  const confidence = normalizeConfidence(item.confidence);
  return {
    id: `apt:${item.packetId}:${item.actorId ?? "unknown"}:${item.sourceModule ?? "unknown"}:${index}`,
    module: normalizeEvidenceModule(item.sourceModule, "apt"),
    sourceModule: item.sourceModule,
    packetId: item.packetId,
    streamId: item.streamId,
    family: item.family,
    actorId: item.actorId,
    actorName: item.actorName,
    sourceType: item.evidenceType || "apt-evidence",
    summary: item.summary || item.evidenceValue || item.evidence || "APT evidence",
    value: item.evidenceValue || item.evidence,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    severity: evidenceSeverityFromConfidence(confidence),
    source: item.source,
    destination: item.destination,
    host: item.host,
    uri: item.uri,
    tags: dedupe(tags),
    caveats: buildCaveats(confidence, item.sourceModule, item.scoreFactors?.filter((factor) => factor.direction === "negative" || factor.direction === "missing").map((factor) => factor.summary || factor.name)),
  };
}

/** @deprecated Use useEvidence hook with backend /api/evidence endpoint instead. */
export function fromC2Indicator(item: C2IndicatorRecord, index = 0): UnifiedEvidenceRecord {
  const confidence = normalizeConfidence(item.confidence ?? item.attributionConfidence);
  return {
    id: `c2:${item.packetId}:${item.family}:${item.indicatorType ?? "indicator"}:${index}`,
    module: "c2",
    sourceModule: "c2-analysis",
    packetId: item.packetId,
    streamId: item.streamId,
    family: item.family,
    sourceType: item.indicatorType || "c2-indicator",
    summary: item.summary || item.indicatorValue || "C2 indicator",
    value: item.indicatorValue || item.evidence,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    severity: evidenceSeverityFromConfidence(confidence),
    source: item.source,
    destination: item.destination,
    host: item.host,
    uri: item.uri,
    tags: dedupe([
      item.channel,
      item.sampleFamily,
      item.campaignStage,
      ...(item.transportTraits ?? []),
      ...(item.infrastructureHints ?? []),
      ...(item.ttpTags ?? []),
      ...(item.tags ?? []),
      ...(item.actorHints ?? []).map((hint) => `actor:${hint}`),
    ].filter(Boolean) as string[]),
    caveats: buildCaveats(confidence, "c2-analysis"),
  };
}

/** @deprecated Use useEvidence hook with backend /api/evidence endpoint instead. */
export function fromThreatHit(item: ThreatHit): UnifiedEvidenceRecord {
  const severity = threatLevelToSeverity(item.level);
  return {
    id: `threat:${item.id}:${item.packetId}`,
    module: "hunting",
    sourceModule: "threat-hunting",
    packetId: item.packetId,
    sourceType: item.category || "threat-hit",
    summary: item.rule || item.preview || "Threat hit",
    value: item.match || item.preview,
    confidenceLabel: "unknown",
    severity,
    tags: dedupe([item.category, item.level, item.rule].filter(Boolean)),
    caveats: ["规则命中仅代表检测信号，需要结合上下文、payload 与会话行为复核。"],
  };
}

function normalizeConfidence(confidence?: number) {
  if (confidence === undefined || Number.isNaN(confidence)) return undefined;
  return Math.max(0, Math.min(100, Math.round(confidence)));
}

function normalizeEvidenceModule(sourceModule: string | undefined, fallback: EvidenceModule): EvidenceModule {
  const normalized = String(sourceModule ?? "").toLowerCase();
  if (normalized.includes("c2")) return "c2";
  if (normalized.includes("apt")) return "apt";
  if (normalized.includes("hunting") || normalized.includes("yara") || normalized.includes("threat")) return "hunting";
  if (normalized.includes("industrial")) return "industrial";
  if (normalized.includes("vehicle")) return "vehicle";
  if (normalized.includes("usb")) return "usb";
  if (normalized.includes("object")) return "object";
  if (normalized.includes("misc") || normalized.includes("webshell") || normalized.includes("decoder")) return "misc";
  if (normalized.includes("stream")) return "stream";
  return fallback;
}

function buildCaveats(confidence?: number, sourceModule?: string, extra: Array<string | undefined> = []) {
  const caveats = [...extra.filter(Boolean)] as string[];
  if (confidence === undefined || confidence <= 0) {
    caveats.push("缺少置信度字段，当前仅作为线索展示。");
  } else if (confidence < 45) {
    caveats.push("低置信信号，必须结合上下文人工复核。");
  } else if (confidence < 75) {
    caveats.push("中置信信号，不应单独作为强归因结论。");
  }
  if (!sourceModule) {
    caveats.push("缺少来源模块标识，证据链追溯能力受限。");
  }
  return dedupe(caveats);
}

function threatLevelToSeverity(level: ThreatLevel): EvidenceSeverity {
  const severityByLevel: Partial<Record<ThreatLevel, EvidenceSeverity>> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
  };
  return severityByLevel[level] ?? "info";
}

function dedupe<T>(items: T[]) {
  return Array.from(new Set(items));
}
