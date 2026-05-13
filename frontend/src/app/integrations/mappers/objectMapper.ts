import type { ExtractedObject } from "../../core/types";
import type { ExtractedObjectWireDTO } from "../wire/evidenceWireDtos";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asObject(input: unknown): ExtractedObject {
  const payload: ExtractedObjectWireDTO | undefined = asPlainObject(input);
  const source = String(payload?.source ?? "HTTP");
  return {
    id: Number(payload?.id ?? 0),
    packetId: Number(payload?.packet_id ?? 0),
    name: String(payload?.name ?? "object.bin"),
    sizeBytes: Number(payload?.size_bytes ?? 0),
    mime: String(payload?.mime ?? "application/octet-stream"),
    magic: String(payload?.magic ?? ""),
    source: source === "FTP" ? "FTP" : "HTTP",
  };
}

export function asObjectList(input: unknown): ExtractedObject[] {
  return asArray(input).map(asObject);
}
