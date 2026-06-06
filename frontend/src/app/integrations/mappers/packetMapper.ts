import type { Packet } from "../../core/types";
import type { PacketColorFeaturesWireDTO, PacketWireDTO, TLSFingerprintWireDTO } from "../wire/captureWireDtos";
import { asPlainObject } from "./mapperPrimitives";
import { asColorFeatures, asTLSFingerprint } from "./packetColorFeatureMapper";
import { asProtocol } from "./packetProtocolMapper";
import { normalizePacketTime } from "./packetTimeMapper";

export function asPacket(input: unknown): Packet {
  const payload: PacketWireDTO = asPlainObject(input) ?? {};
  const color: PacketColorFeaturesWireDTO = asPlainObject(payload.color_features) ?? {};
  const tlsFingerprint: TLSFingerprintWireDTO = asPlainObject(payload.tls_fingerprint) ?? {};
  return {
    id: Number(payload.id ?? 0),
    time: normalizePacketTime(payload.timestamp),
    src: String(payload.source_ip ?? ""),
    srcPort: Number(payload.source_port ?? 0),
    dst: String(payload.dest_ip ?? ""),
    dstPort: Number(payload.dest_port ?? 0),
    proto: asProtocol(payload.protocol),
    displayProtocol: String(payload.display_protocol ?? "").trim() || undefined,
    length: Number(payload.length ?? 0),
    info: String(payload.info ?? ""),
    payload: String(payload.payload ?? ""),
    rawHex: String(payload.raw_hex ?? "") || undefined,
    streamId: Number(payload.stream_id ?? 0),
    ipHeaderLen: Number(payload.ip_header_len ?? 0) || undefined,
    l4HeaderLen: Number(payload.l4_header_len ?? 0) || undefined,
    colorFeatures: asColorFeatures(color),
    tlsFingerprint: asTLSFingerprint(tlsFingerprint),
  };
}
