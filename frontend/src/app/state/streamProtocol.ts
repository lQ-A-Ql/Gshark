import type { Packet } from "../core/types";

export type StreamDisplayProtocol = "HTTP" | "TCP" | "UDP";

export function resolvePacketStreamProtocol(
  packetProto: Packet["proto"],
  preferred?: StreamDisplayProtocol | null,
): StreamDisplayProtocol {
  if (preferred) {
    return preferred;
  }
  if (packetProto === "HTTP") {
    return "HTTP";
  }
  if (packetProto === "UDP") {
    return "UDP";
  }
  return "TCP";
}
