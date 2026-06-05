import { confidenceLabel } from "../../core/types";
import type {
  EvidenceMetadata,
  EvidenceMetadataValue,
  EvidenceModule,
  EvidenceSeverity,
  UnifiedEvidenceRecord,
} from "../../core/types";
import type { EvidenceListWireDTO, UnifiedEvidenceRecordWireDTO } from "../wire/evidenceWireDtos";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

const VALID_SEVERITIES = new Set<string>(["critical", "high", "medium", "low", "info"]);

function asEvidenceSeverity(raw: unknown): EvidenceSeverity {
  const s = String(raw ?? "info").toLowerCase();
  return VALID_SEVERITIES.has(s) ? (s as EvidenceSeverity) : "info";
}

export function parseEvidenceRecords(input: unknown): UnifiedEvidenceRecord[] {
  const payload: EvidenceListWireDTO | undefined = asPlainObject(input);
  return asArray(payload?.records).map(asEvidenceRecord);
}

function asEvidenceRecord(input: unknown): UnifiedEvidenceRecord {
  const item: UnifiedEvidenceRecordWireDTO | undefined = asPlainObject(input);
  const confidence = typeof item?.confidence === "number" ? item.confidence : undefined;
  return {
    id: String(item?.id ?? ""),
    module: normalizeEvidenceModule(String(item?.module ?? "unknown")),
    sourceModule: String(item?.source_module ?? "") || undefined,
    packetId: Number(item?.packet_id ?? 0) || undefined,
    streamId: Number(item?.stream_id ?? 0) || undefined,
    family: String(item?.family ?? "") || undefined,
    feature: String(item?.feature ?? "") || undefined,
    entityType: String(item?.entity_type ?? "") || undefined,
    protocol: String(item?.protocol ?? "") || undefined,
    version: String(item?.version ?? "") || undefined,
    displayName: String(item?.display_name ?? "") || undefined,
    ruleId: String(item?.rule_id ?? "") || undefined,
    ruleName: String(item?.rule_name ?? "") || undefined,
    playbookId: String(item?.playbook_id ?? "") || undefined,
    playbookName: String(item?.playbook_name ?? "") || undefined,
    iocType: String(item?.ioc_type ?? "") || undefined,
    iocValue: String(item?.ioc_value ?? "") || undefined,
    ja3Hash: String(item?.ja3_hash ?? "") || undefined,
    ja3sHash: String(item?.ja3s_hash ?? "") || undefined,
    metadata: asEvidenceMetadata(item?.metadata),
    actorId: String(item?.actor_id ?? "") || undefined,
    actorName: String(item?.actor_name ?? "") || undefined,
    sourceType: String(item?.source_type ?? ""),
    summary: String(item?.summary ?? ""),
    value: String(item?.value ?? "") || undefined,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    severity: asEvidenceSeverity(item?.severity),
    source: String(item?.source ?? "") || undefined,
    destination: String(item?.destination ?? "") || undefined,
    host: String(item?.host ?? "") || undefined,
    uri: String(item?.uri ?? "") || undefined,
    tags: asStringList(item?.tags),
    caveats: asStringList(item?.caveats),
  };
}

function asEvidenceMetadata(input: unknown): EvidenceMetadata | undefined {
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

export function normalizeEvidenceModule(raw: string): EvidenceModule {
  const lower = raw.toLowerCase();
  if (lower.includes("c2")) return "c2";
  if (lower.includes("apt")) return "apt";
  if (lower.includes("hunting") || lower.includes("yara") || lower.includes("threat")) return "hunting";
  if (lower.includes("industrial")) return "industrial";
  if (lower.includes("vehicle")) return "vehicle";
  if (lower.includes("usb")) return "usb";
  if (lower.includes("media") || lower.includes("speech") || lower.includes("rtp")) return "media";
  if (lower.includes("object")) return "object";
  if (lower.includes("misc") || lower.includes("webshell") || lower.includes("decoder")) return "misc";
  if (lower.includes("stream")) return "stream";
  return "unknown";
}
