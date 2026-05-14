import type { ShiroRememberMeAnalysis } from "../../core/types";
import type { ShiroRememberMeAnalysisWireDTO } from "../wire/protocolToolWireDtos";
import type { ShiroKeyResultWireDTO, ShiroRememberMeCandidateWireDTO } from "../wire/shiroWireDtos";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asPlainObject, asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

export function asShiroRememberMeAnalysis(input: unknown): ShiroRememberMeAnalysis {
  const payload: ShiroRememberMeAnalysisWireDTO = asPlainObject(input) ?? {};
  return {
    candidateCount: Number(payload.candidate_count ?? 0),
    hitCount: Number(payload.hit_count ?? 0),
    candidates: asArray(payload.candidates).map(asShiroRememberMeCandidate),
    notes: asStringList(payload.notes),
    report: asInvestigationReport(payload.report),
  };
}

function asShiroRememberMeCandidate(input: unknown) {
  const item: ShiroRememberMeCandidateWireDTO = asPlainObject(input) ?? {};
  return {
    packetId: Number(item.packet_id ?? 0),
    streamId: optionalNumber(item.stream_id),
    time: optionalString(item.time),
    src: optionalString(item.src),
    dst: optionalString(item.dst),
    host: optionalString(item.host),
    path: optionalString(item.path),
    sourceHeader: optionalString(item.source_header),
    cookieName: optionalString(item.cookie_name),
    cookieValue: optionalString(item.cookie_value),
    cookiePreview: optionalString(item.cookie_preview),
    decodeOK: Boolean(item.decode_ok),
    encryptedLength: optionalNumber(item.encrypted_length),
    aesBlockAligned: Boolean(item.aes_block_aligned),
    possibleCBC: Boolean(item.possible_cbc),
    possibleGCM: Boolean(item.possible_gcm),
    keyResults: asArray(item.key_results).map(asShiroKeyResult),
    hitCount: optionalNumber(item.hit_count),
    notes: asStringList(item.notes),
  };
}

function asShiroKeyResult(input: unknown) {
  const row: ShiroKeyResultWireDTO = asPlainObject(input) ?? {};
  return {
    label: String(row.label ?? ""),
    base64: optionalString(row.base64),
    algorithm: optionalString(row.algorithm),
    hit: Boolean(row.hit),
    payloadClass: optionalString(row.payload_class),
    preview: optionalString(row.preview),
    reason: optionalString(row.reason),
  };
}
