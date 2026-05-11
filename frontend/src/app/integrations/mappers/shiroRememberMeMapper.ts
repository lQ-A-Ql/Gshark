import type { ShiroRememberMeAnalysis } from "../../core/types";
import { asInvestigationReport } from "./investigationReportMapper";
import { asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

export function asShiroRememberMeAnalysis(input: any): ShiroRememberMeAnalysis {
  return {
    candidateCount: Number(input.candidate_count ?? 0),
    hitCount: Number(input.hit_count ?? 0),
    candidates: Array.isArray(input.candidates)
      ? input.candidates.map((item: any) => ({
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
          keyResults: Array.isArray(item.key_results)
            ? item.key_results.map((row: any) => ({
                label: String(row.label ?? ""),
                base64: optionalString(row.base64),
                algorithm: optionalString(row.algorithm),
                hit: Boolean(row.hit),
                payloadClass: optionalString(row.payload_class),
                preview: optionalString(row.preview),
                reason: optionalString(row.reason),
              }))
            : [],
          hitCount: optionalNumber(item.hit_count),
          notes: asStringList(item.notes),
        }))
      : [],
    notes: asStringList(input.notes),
    report: asInvestigationReport(input.report),
  };
}
