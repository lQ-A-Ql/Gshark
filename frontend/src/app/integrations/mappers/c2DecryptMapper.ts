import type { C2DecryptedRecord } from "../../core/types";

export function asC2DecryptedRecord(item: any): C2DecryptedRecord {
  return {
    packetId: Number(item.packet_id ?? 0) || undefined,
    streamId: Number(item.stream_id ?? 0) || undefined,
    time: String(item.time ?? "") || undefined,
    direction: String(item.direction ?? "") || undefined,
    algorithm: String(item.algorithm ?? "") || undefined,
    keyStatus: String(item.key_status ?? "") || undefined,
    confidence: Number(item.confidence ?? 0),
    plaintextPreview: String(item.plaintext_preview ?? "") || undefined,
    parsed: item.parsed && typeof item.parsed === "object" && !Array.isArray(item.parsed) ? item.parsed : undefined,
    rawLength: Number(item.raw_length ?? 0) || undefined,
    decryptedLength: Number(item.decrypted_length ?? 0) || undefined,
    tags: Array.isArray(item.tags) ? item.tags.map((value: unknown) => String(value ?? "")) : [],
    error: String(item.error ?? "") || undefined,
  };
}
