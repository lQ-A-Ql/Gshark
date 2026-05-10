import { LAYER_TITLES } from "./protocolDisplay";
import { computePacketByteLayout, parsePayloadBytes } from "./packetByteLayout";
import type { Packet, ProtocolTreeNode } from "./types";

export function buildProtocolTree(packet: Packet | null): ProtocolTreeNode[] {
  if (!packet) return [];

  const payloadBytes = parsePayloadBytes(packet.payload);
  const layout = computePacketByteLayout(packet);
  const onWireBits = packet.length * 8;
  const payloadPreview = payloadBytes
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");

  return [
    {
      id: "frame",
      label: `Frame ${packet.id}: ${packet.length} bytes on wire (${onWireBits} bits)`,
      byteRange: layout.frameRange,
      children: [
        { id: "frame-time", label: `Arrival Time: ${packet.time || "N/A"}` },
        { id: "frame-proto", label: `Protocols in frame: ${packet.displayProtocol || packet.proto || "N/A"}` },
        { id: "frame-info", label: `Info: ${packet.info || "N/A"}` },
      ],
    },
    {
      id: "ip",
      label: `${layout.isIPv6 ? "Internet Protocol Version 6" : "Internet Protocol Version 4"}, Src: ${packet.src}, Dst: ${packet.dst}`,
      byteRange: layout.ipRange,
      children: [
        { id: "ip-ver", label: `Version: ${layout.isIPv6 ? 6 : 4}`, byteRange: [layout.ipRange[0], layout.ipRange[0]] },
        { id: "ip-src", label: `Source Address: ${packet.src}` },
        { id: "ip-dst", label: `Destination Address: ${packet.dst}` },
      ],
    },
    {
      id: "l4",
      label: `${transportLayerTitle(packet.proto)}, Src Port: ${packet.srcPort}, Dst Port: ${packet.dstPort}`,
      byteRange: layout.transportRange,
      children: [
        { id: "l4-src", label: `Source Port: ${packet.srcPort}` },
        { id: "l4-dst", label: `Destination Port: ${packet.dstPort}` },
        { id: "l4-stream", label: `Stream ID: ${packet.streamId ?? "N/A"}` },
      ],
    },
    {
      id: "app",
      label: `${packet.displayProtocol || "Application Data"} (${payloadBytes.length} bytes)`,
      byteRange: payloadBytes.length > 0 ? layout.payloadRange : undefined,
      children: [{ id: "payload-preview", label: `Payload Preview: ${payloadPreview || "(empty)"}` }],
    },
  ];
}

function transportLayerTitle(proto: string): string {
  const normalized = proto.toLowerCase();
  return LAYER_TITLES[normalized] ?? proto;
}
