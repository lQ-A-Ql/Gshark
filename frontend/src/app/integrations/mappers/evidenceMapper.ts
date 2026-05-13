import { confidenceLabel } from "../../core/types";
import type { EvidenceModule, UnifiedEvidenceRecord } from "../../core/types";
import type { EvidenceListWireDTO, UnifiedEvidenceRecordWireDTO } from "../wire/evidenceWireDtos";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

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
    actorId: String(item?.actor_id ?? "") || undefined,
    actorName: String(item?.actor_name ?? "") || undefined,
    sourceType: String(item?.source_type ?? ""),
    summary: String(item?.summary ?? ""),
    value: String(item?.value ?? "") || undefined,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    severity: String(item?.severity ?? "info") as UnifiedEvidenceRecord["severity"],
    source: String(item?.source ?? "") || undefined,
    destination: String(item?.destination ?? "") || undefined,
    host: String(item?.host ?? "") || undefined,
    uri: String(item?.uri ?? "") || undefined,
    tags: asStringList(item?.tags),
    caveats: asStringList(item?.caveats),
  };
}

export function normalizeEvidenceModule(raw: string): EvidenceModule {
  const lower = raw.toLowerCase();
  if (lower.includes("c2")) return "c2";
  if (lower.includes("apt")) return "apt";
  if (lower.includes("hunting") || lower.includes("yara") || lower.includes("threat")) return "hunting";
  if (lower.includes("industrial")) return "industrial";
  if (lower.includes("vehicle")) return "vehicle";
  if (lower.includes("usb")) return "usb";
  if (lower.includes("object")) return "object";
  if (lower.includes("misc") || lower.includes("webshell") || lower.includes("decoder")) return "misc";
  if (lower.includes("stream")) return "stream";
  return "unknown";
}
