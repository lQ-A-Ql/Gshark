import type { C2DecryptedRecord } from "../../core/types";
import { asPlainObject, asStringList } from "./mapperPrimitives";

export function asC2DecryptedRecord(item: unknown): C2DecryptedRecord {
  const payload = asPlainObject(item) ?? {};
  const parsed = asPlainObject(payload.parsed);
  return {
    packetId: Number(payload.packet_id ?? 0) || undefined,
    streamId: Number(payload.stream_id ?? 0) || undefined,
    time: String(payload.time ?? "") || undefined,
    direction: String(payload.direction ?? "") || undefined,
    algorithm: String(payload.algorithm ?? "") || undefined,
    keyStatus: String(payload.key_status ?? "") || undefined,
    confidence: Number(payload.confidence ?? 0),
    plaintextPreview: String(payload.plaintext_preview ?? "") || undefined,
    parsed,
    rawLength: Number(payload.raw_length ?? 0) || undefined,
    decryptedLength: Number(payload.decrypted_length ?? 0) || undefined,
    tags: asStringList(payload.tags),
    error: String(payload.error ?? "") || undefined,
  };
}
