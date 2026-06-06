import { confidenceLabel } from "../../core/types";
import type { UnifiedEvidenceRecord } from "../../core/types";
import type { EvidenceListWireDTO, UnifiedEvidenceRecordWireDTO } from "../wire/evidenceWireDtos";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";
import { asEvidenceMetadata } from "./evidenceMetadataMapper";
export { normalizeEvidenceModule } from "./evidenceModuleMapper";
import { normalizeEvidenceModule } from "./evidenceModuleMapper";
import { asEvidenceSeverity } from "./evidenceSeverityMapper";

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
