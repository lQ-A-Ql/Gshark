import type { Packet } from "./types";

export type PacketByteLayout = ReturnType<typeof computePacketByteLayout>;

export function buildHexDump(packet: Packet | null): string {
  if (!packet) return "";

  const headerText =
    `Frame ${packet.id} ${packet.proto} Len=${packet.length}\n` +
    `Time=${packet.time} ${packet.src}:${packet.srcPort} -> ${packet.dst}:${packet.dstPort}\n` +
    `Info=${packet.info || "N/A"}\n`;

  const headerBytes = Array.from(new TextEncoder().encode(headerText));
  const payloadBytes = parsePayloadBytes(packet.payload);
  const bytes = [...headerBytes, ...payloadBytes];

  if (bytes.length === 0) return "暂无 hex 数据";

  const lines: string[] = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }

  return lines.join("\n");
}

export function parsePayloadBytes(payload: string): number[] {
  const raw = (payload ?? "").trim();
  if (!raw) return [];

  const hexLike = /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw);
  if (hexLike) {
    return raw
      .split(":")
      .map((part) => Number.parseInt(part, 16))
      .filter((v) => Number.isFinite(v));
  }

  return Array.from(new TextEncoder().encode(raw));
}

export function computePacketByteLayout(packet: Packet) {
  const totalEnd = Math.max(packet.length - 1, 0);
  const frameRange: [number, number] = [0, totalEnd];
  const ethernetEnd = Math.min(13, totalEnd);
  const isIPv6 = packet.src.includes(":") || packet.dst.includes(":");
  const ipHeaderLen = packet.ipHeaderLen && packet.ipHeaderLen > 0 ? packet.ipHeaderLen : isIPv6 ? 40 : 20;
  const ipStart = Math.min(ethernetEnd + 1, totalEnd);
  const ipEnd = Math.min(ipStart + Math.max(ipHeaderLen - 1, 0), totalEnd);
  const l4HeaderLen =
    packet.l4HeaderLen && packet.l4HeaderLen > 0
      ? packet.l4HeaderLen
      : packet.proto === "UDP"
        ? 8
        : packet.proto === "TCP"
          ? 20
          : packet.proto === "ICMP" || packet.proto === "ICMPV6"
            ? 8
            : 0;
  const transportStart = Math.min(ipEnd + 1, totalEnd);
  const transportEnd =
    l4HeaderLen > 0 ? Math.min(transportStart + Math.max(l4HeaderLen - 1, 0), totalEnd) : transportStart;
  const payloadStart = Math.min(transportEnd + 1, totalEnd);
  const payloadRange: [number, number] = [payloadStart, totalEnd];

  return {
    isIPv6,
    frameRange,
    ethernetRange: [0, ethernetEnd] as [number, number],
    ipRange: [ipStart, ipEnd] as [number, number],
    transportRange: [transportStart, transportEnd] as [number, number],
    payloadRange,
  };
}
