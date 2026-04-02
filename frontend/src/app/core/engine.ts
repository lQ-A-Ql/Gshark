import type { Packet, ProtocolTreeNode } from "./types";

export function buildProtocolTree(packet: Packet | null): ProtocolTreeNode[] {
  if (!packet) return [];

  const payloadBytes = parsePayloadBytes(packet.payload);
  const layout = computePacketByteLayout(packet);
  const payloadPreview = payloadBytes
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");

  return [
    {
      id: "frame",
      label: `Frame ${packet.id}: ${packet.length} bytes on wire`,
      byteRange: layout.frameRange,
      children: [
        { id: "frame-time", label: `Time: ${packet.time || "N/A"}` },
        { id: "frame-info", label: `Info: ${packet.info || "N/A"}` },
      ],
    },
    {
      id: "ip",
      label: `${layout.isIPv6 ? "IPv6" : "IPv4"} Src ${packet.src} -> Dst ${packet.dst}`,
      byteRange: layout.ipRange,
      children: [
        { id: "ip-ver", label: `Version: ${layout.isIPv6 ? 6 : 4}`, byteRange: [layout.ipRange[0], layout.ipRange[0]] },
        { id: "ip-src", label: `Source: ${packet.src}` },
        { id: "ip-dst", label: `Destination: ${packet.dst}` },
      ],
    },
    {
      id: "l4",
      label: `${packet.proto} Src Port ${packet.srcPort} -> Dst Port ${packet.dstPort}`,
      byteRange: layout.transportRange,
      children: [
        { id: "l4-src", label: `Source Port: ${packet.srcPort}` },
        { id: "l4-dst", label: `Destination Port: ${packet.dstPort}` },
        { id: "l4-stream", label: `Stream ID: ${packet.streamId ?? "N/A"}` },
      ],
    },
    {
      id: "app",
      label: `Payload (${payloadBytes.length} bytes)`,
      byteRange: payloadBytes.length > 0 ? layout.payloadRange : undefined,
      children: [
        { id: "payload-preview", label: `Preview: ${payloadPreview || "(empty)"}` },
      ],
    },
  ];
}

export function buildProtocolTreeFromLayers(layers: unknown, packet: Packet | null): ProtocolTreeNode[] {
  if (!isRecord(layers)) {
    return buildProtocolTree(packet);
  }

  const layout = packet ? computePacketByteLayout(packet) : null;
  const entries = Object.entries(layers);
  const layerNodes = entries.map(([key, value], index) =>
    toTreeNode(String(key), value, `layer-${index}`, resolveLayerByteRange(String(key), layout)),
  );

  if (!packet || entries.some(([key]) => String(key).toLowerCase() === "frame")) {
    return layerNodes;
  }

  return [
    {
      id: "frame",
      label: `Frame ${packet.id}: ${packet.length} bytes on wire`,
      byteRange: layout?.frameRange ?? [0, Math.max(packet.length - 1, 0)],
      children: [
        { id: "frame-time", label: `Time: ${packet.time || "N/A"}` },
        { id: "frame-info", label: `Info: ${packet.info || "N/A"}` },
      ],
    },
    ...layerNodes,
  ];
}

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
    const ascii = chunk
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }

  return lines.join("\n");
}

function parsePayloadBytes(payload: string): number[] {
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

function toTreeNode(name: string, value: unknown, id: string, byteRange?: [number, number]): ProtocolTreeNode {
  if (Array.isArray(value)) {
    const children = value.map((item, idx) => toTreeNode(`[${idx}]`, item, `${id}-${idx}`, byteRange));
    return {
      id,
      label: `${name} (${value.length})`,
      byteRange,
      children,
    };
  }

  if (isRecord(value)) {
    const entries = Object.entries(value);
    const children = entries.map(([k, v], idx) =>
      toTreeNode(String(k), v, `${id}-${idx}`, resolveChildByteRange(String(k), byteRange)),
    );
    return {
      id,
      label: name,
      byteRange,
      children,
    };
  }

  return {
    id,
    byteRange,
    label: `${name}: ${formatLeafValue(value)}`,
  };
}

function computePacketByteLayout(packet: Packet) {
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
    l4HeaderLen > 0
      ? Math.min(transportStart + Math.max(l4HeaderLen - 1, 0), totalEnd)
      : transportStart;
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

function resolveLayerByteRange(
  layerName: string,
  layout: ReturnType<typeof computePacketByteLayout> | null,
): [number, number] | undefined {
  if (!layout) return undefined;
  const name = layerName.toLowerCase();

  if (name === "frame") return layout.frameRange;
  if (name === "eth" || name === "sll" || name === "sll2") return layout.ethernetRange;
  if (name === "ip" || name === "ipv4" || name === "ipv6") return layout.ipRange;
  if (name === "tcp" || name === "udp" || name === "icmp" || name === "icmpv6") return layout.transportRange;
  if (
    name === "http" ||
    name === "tls" ||
    name === "ssl" ||
    name === "data" ||
    name === "dns" ||
    name === "quic" ||
    name === "ssh" ||
    name === "ftp" ||
    name === "smb" ||
    name === "smb2" ||
    name === "nbss" ||
    name === "nbns"
  ) {
    return layout.payloadRange;
  }
  return undefined;
}

function resolveChildByteRange(name: string, inheritedRange?: [number, number]): [number, number] | undefined {
  if (!inheritedRange) return undefined;
  const normalized = name.toLowerCase();
  if (
    normalized.includes("payload") ||
    normalized.includes("segment_data") ||
    normalized.includes("app_data") ||
    normalized.includes("reassembled") ||
    normalized.includes("file_data")
  ) {
    return inheritedRange;
  }
  return inheritedRange;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatLeafValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `${value.length} items`;
  if (isRecord(value)) return "{...}";
  return String(value);
}

export const DEFAULT_PLUGIN_LOGS = [
  "[INFO] 插件引擎启动完成",
  "[INFO] 规则加载: 131 条",
  "[DEBUG] 等待数据流输入",
];
