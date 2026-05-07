import type { ExtractedObject } from "../../core/types";

export function asObject(input: any): ExtractedObject {
  const source = String(input.source ?? "HTTP");
  return {
    id: Number(input.id ?? 0),
    packetId: Number(input.packet_id ?? 0),
    name: String(input.name ?? "object.bin"),
    sizeBytes: Number(input.size_bytes ?? 0),
    mime: String(input.mime ?? "application/octet-stream"),
    magic: String(input.magic ?? ""),
    source: source === "FTP" ? "FTP" : "HTTP",
  };
}

export function asObjectList(input: any): ExtractedObject[] {
  return Array.isArray(input) ? input.map(asObject) : [];
}
