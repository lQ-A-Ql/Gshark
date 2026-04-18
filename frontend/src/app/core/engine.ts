import type { Packet, ProtocolTreeNode } from "./types";

const LAYER_TITLES: Record<string, string> = {
  frame: "Frame",
  eth: "Ethernet II",
  sll: "Linux cooked capture",
  sll2: "Linux cooked capture v2",
  ip: "Internet Protocol Version 4",
  ipv4: "Internet Protocol Version 4",
  ipv6: "Internet Protocol Version 6",
  tcp: "Transmission Control Protocol",
  udp: "User Datagram Protocol",
  http: "Hypertext Transfer Protocol",
  tls: "Transport Layer Security",
  ssl: "Secure Sockets Layer",
  dns: "Domain Name System",
  arp: "Address Resolution Protocol",
  icmp: "Internet Control Message Protocol",
  icmpv6: "Internet Control Message Protocol v6",
  igmp: "Internet Group Management Protocol",
  smb: "Server Message Block",
  smb2: "Server Message Block v2",
  quic: "Quick UDP Internet Connections",
  ssh: "Secure Shell",
  ftp: "File Transfer Protocol",
  data: "Data",
};

const TOKEN_LABELS: Record<string, string> = {
  addr: "Address",
  ack: "ACK",
  ascii: "ASCII",
  cap: "Captured",
  checksum: "Checksum",
  crc: "CRC",
  df: "DF",
  dns: "DNS",
  dst: "Dst",
  ecn: "ECN",
  eth: "Ethernet",
  frame: "Frame",
  hdr: "Header",
  host: "Host",
  http: "HTTP",
  icmp: "ICMP",
  icmpv6: "ICMPv6",
  id: "ID",
  igmp: "IGMP",
  ip: "IP",
  ipv6: "IPv6",
  len: "Length",
  lg: "LG",
  mac: "MAC",
  mf: "MF",
  oui: "OUI",
  port: "Port",
  proto: "Protocol",
  raw: "Raw",
  rb: "RB",
  seq: "Seq",
  smb: "SMB",
  smb2: "SMB2",
  src: "Src",
  ssl: "SSL",
  stream: "Stream",
  tcp: "TCP",
  tls: "TLS",
  ttl: "TTL",
  udp: "UDP",
  uri: "URI",
  utc: "UTC",
  ver: "Version",
};

const HIDDEN_LAYER_KEYS = new Set([
  "_ws_lua__ws_lua_fake",
]);

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
      children: [
        { id: "payload-preview", label: `Payload Preview: ${payloadPreview || "(empty)"}` },
      ],
    },
  ];
}

export function buildProtocolTreeFromLayers(layers: unknown, packet: Packet | null): ProtocolTreeNode[] {
  if (!isRecord(layers)) {
    return buildProtocolTree(packet);
  }

  const layout = packet ? computePacketByteLayout(packet) : null;
  const entries = orderLayerEntries(layers);
  if (entries.length === 0) {
    return buildProtocolTree(packet);
  }

  const layerNodes = entries.map(([key, value], index) =>
    buildLayerTreeNode(String(key), value, `layer-${index}`, resolveLayerByteRange(String(key), layout), packet),
  );

  if (!packet || entries.some(([key]) => normalizeLayerName(String(key)) === "frame")) {
    return layerNodes;
  }

  return [
    {
      id: "frame",
      label: `Frame ${packet.id}: ${packet.length} bytes on wire (${packet.length * 8} bits)`,
      byteRange: layout?.frameRange ?? [0, Math.max(packet.length - 1, 0)],
      children: [
        { id: "frame-time", label: `Arrival Time: ${packet.time || "N/A"}` },
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

function buildLayerTreeNode(
  layerName: string,
  value: unknown,
  id: string,
  byteRange: [number, number] | undefined,
  packet: Packet | null,
): ProtocolTreeNode {
  const normalizedLayer = normalizeLayerName(layerName);
  if (!isRecord(value)) {
    return {
      id,
      byteRange,
      label: `${layerTitle(normalizedLayer)}: ${formatLeafValue(value)}`,
    };
  }

  const fields = orderLayerFields(normalizedLayer, value);
  return {
    id,
    label: summarizeLayer(normalizedLayer, value, packet),
    byteRange,
    children: fields.map(([fieldKey, fieldValue], index) =>
      toFieldTreeNode(normalizedLayer, String(fieldKey), fieldValue, `${id}-${index}`, resolveChildByteRange(String(fieldKey), byteRange)),
    ),
  };
}

function toFieldTreeNode(
  layerName: string,
  fieldName: string,
  value: unknown,
  id: string,
  byteRange?: [number, number],
): ProtocolTreeNode {
  const strippedName = stripLayerPrefix(fieldName, layerName);
  if (Array.isArray(value)) {
    if (value.every((item) => !isRecord(item) && !Array.isArray(item))) {
      const rendered = value.map((item) => formatLeafValue(item)).filter(Boolean);
      return {
        id,
        byteRange,
        label: buildFieldLabel(strippedName, rendered.join(", ")),
      };
    }
    return {
      id,
      byteRange,
      label: `${humanizeFieldName(strippedName)} (${value.length})`,
      children: value.map((item, idx) => toFieldTreeNode(layerName, `[${idx}]`, item, `${id}-${idx}`, byteRange)),
    };
  }

  if (isRecord(value)) {
    const entries = Object.entries(value);
    return {
      id,
      byteRange,
      label: humanizeFieldName(strippedName),
      children: entries.map(([key, child], idx) =>
        toFieldTreeNode(layerName, String(key), child, `${id}-${idx}`, byteRange),
      ),
    };
  }

  if (strippedName.toLowerCase() === "text") {
    return {
      id,
      byteRange,
      label: formatLeafValue(value),
    };
  }

  return {
    id,
    byteRange,
    label: buildFieldLabel(strippedName, formatLeafValue(value)),
  };
}

function orderLayerEntries(layers: Record<string, unknown>): Array<[string, unknown]> {
  const filtered = Object.entries(layers).filter(([key, value]) => !shouldHideLayer(key, value));
  if (filtered.length === 0) {
    return [];
  }

  const originalIndices = new Map(filtered.map(([key], index) => [key, index]));
  const protocolOrder = extractLayerOrder(layers);
  const rank = new Map(protocolOrder.map((name, index) => [name, index]));

  return filtered.sort(([leftKey], [rightKey]) => {
    const leftRank = rank.get(normalizeLayerName(leftKey)) ?? Number.MAX_SAFE_INTEGER;
    const rightRank = rank.get(normalizeLayerName(rightKey)) ?? Number.MAX_SAFE_INTEGER;
    if (leftRank !== rightRank) {
      return leftRank - rightRank;
    }
    return (originalIndices.get(leftKey) ?? 0) - (originalIndices.get(rightKey) ?? 0);
  });
}

function orderLayerFields(layerName: string, layer: Record<string, unknown>): Array<[string, unknown]> {
  const entries = Object.entries(layer).filter(([, value]) => value != null);
  const originalIndices = new Map(entries.map(([key], index) => [key, index]));

  return entries.sort(([leftKey], [rightKey]) => {
    const leftWeight = fieldSortWeight(layerName, leftKey);
    const rightWeight = fieldSortWeight(layerName, rightKey);
    if (leftWeight !== rightWeight) {
      return leftWeight - rightWeight;
    }
    const leftLabel = humanizeFieldName(stripLayerPrefix(leftKey, layerName));
    const rightLabel = humanizeFieldName(stripLayerPrefix(rightKey, layerName));
    if (leftLabel !== rightLabel) {
      return leftLabel.localeCompare(rightLabel);
    }
    return (originalIndices.get(leftKey) ?? 0) - (originalIndices.get(rightKey) ?? 0);
  });
}

function fieldSortWeight(layerName: string, fieldName: string): number {
  const name = stripLayerPrefix(fieldName, layerName).toLowerCase();
  if (name === "text") return -10;
  if (name.includes("number")) return -6;
  if (name.includes("time")) return -5;
  if (name.includes("version")) return -4;
  if (name.includes("src") || name.includes("dst")) return -3;
  if (name.includes("port")) return -2;
  if (name.includes("protocol")) return -1;
  return 10;
}

function summarizeLayer(layerName: string, layer: Record<string, unknown>, packet: Packet | null): string {
  switch (layerName) {
    case "frame": {
      const number = pickLayerValue(layer, ["frame_frame_number", "frame.number"]) ?? String(packet?.id ?? "?");
      const wireLength = pickLayerValue(layer, ["frame_frame_len", "frame.len"]) ?? String(packet?.length ?? 0);
      const capturedLength = pickLayerValue(layer, ["frame_frame_cap_len", "frame.cap_len"]) ?? wireLength;
      const wireBits = toInteger(wireLength) * 8;
      const capturedBits = toInteger(capturedLength) * 8;
      return `Frame ${number}: ${wireLength} bytes on wire (${wireBits} bits), ${capturedLength} bytes captured (${capturedBits} bits)`;
    }
    case "eth":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["eth_eth_src_resolved", "eth_eth_src", "eth.src_resolved", "eth.src"]) || "unknown"}, Dst: ${pickLayerValue(layer, ["eth_eth_dst_resolved", "eth_eth_dst", "eth.dst_resolved", "eth.dst"]) || "unknown"}`;
    case "ip":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["ip_ip_src_host", "ip_ip_src", "ip.src_host", "ip.src"]) || packet?.src || "unknown"}, Dst: ${pickLayerValue(layer, ["ip_ip_dst_host", "ip_ip_dst", "ip.dst_host", "ip.dst"]) || packet?.dst || "unknown"}`;
    case "ipv6":
      return `${layerTitle(layerName)}, Src: ${pickLayerValue(layer, ["ipv6_ipv6_src_host", "ipv6_ipv6_src", "ipv6.src_host", "ipv6.src"]) || packet?.src || "unknown"}, Dst: ${pickLayerValue(layer, ["ipv6_ipv6_dst_host", "ipv6_ipv6_dst", "ipv6.dst_host", "ipv6.dst"]) || packet?.dst || "unknown"}`;
    case "tcp":
      return `${layerTitle(layerName)}, Src Port: ${pickLayerValue(layer, ["tcp_tcp_srcport", "tcp.srcport"]) || packet?.srcPort || "?"}, Dst Port: ${pickLayerValue(layer, ["tcp_tcp_dstport", "tcp.dstport"]) || packet?.dstPort || "?"}`;
    case "udp":
      return `${layerTitle(layerName)}, Src Port: ${pickLayerValue(layer, ["udp_udp_srcport", "udp.srcport"]) || packet?.srcPort || "?"}, Dst Port: ${pickLayerValue(layer, ["udp_udp_dstport", "udp.dstport"]) || packet?.dstPort || "?"}`;
    case "http": {
      const method = pickLayerValue(layer, ["http_http_request_method", "http.request.method"]);
      const uri = pickLayerValue(layer, ["http_http_request_full_uri", "http_http_request_uri", "http.request.uri"]);
      const status = pickLayerValue(layer, ["http_http_response_code", "http.response.code"]);
      if (method || uri) {
        return `${layerTitle(layerName)}${method || uri ? `: ${[method, uri].filter(Boolean).join(" ")}` : ""}`;
      }
      if (status) {
        return `${layerTitle(layerName)}: ${status}`;
      }
      return layerTitle(layerName);
    }
    case "igmp": {
      const version = pickLayerValue(layer, ["igmp_igmp_version"]);
      return version ? `${layerTitle(layerName)} v${version}` : layerTitle(layerName);
    }
    default: {
      const summaryText = pickLayerValue(layer, ["text"]);
      return summaryText ? `${layerTitle(layerName)}: ${summaryText}` : layerTitle(layerName);
    }
  }
}

function pickLayerValue(layer: Record<string, unknown>, candidates: string[]): string {
  for (const candidate of candidates) {
    const normalizedCandidate = candidate.toLowerCase();
    for (const [key, value] of Object.entries(layer)) {
      const normalizedKey = key.toLowerCase();
      if (normalizedKey === normalizedCandidate || normalizedKey.endsWith(normalizedCandidate)) {
        const rendered = summarizeFieldValue(value);
        if (rendered) {
          return rendered;
        }
      }
    }
  }
  return "";
}

function summarizeFieldValue(value: unknown): string {
  if (Array.isArray(value)) {
    const items = value.map((item) => formatLeafValue(item)).filter(Boolean);
    return items.join(", ");
  }
  return formatLeafValue(value);
}

function extractLayerOrder(layers: Record<string, unknown>): string[] {
  const frame = Object.entries(layers).find(([key, value]) => normalizeLayerName(key) === "frame" && isRecord(value))?.[1];
  const protocols = frame && isRecord(frame)
    ? pickLayerValue(frame, ["frame_frame_protocols", "frame.protocols"])
    : "";

  const seen = new Set<string>();
  const ordered: string[] = [];
  const push = (name: string) => {
    const normalized = normalizeLayerName(name);
    if (!normalized || normalized === "ethertype" || seen.has(normalized)) return;
    seen.add(normalized);
    ordered.push(normalized);
  };

  push("frame");
  for (const token of protocols.split(":")) {
    push(token);
  }
  for (const key of Object.keys(layers)) {
    push(key);
  }
  return ordered;
}

function shouldHideLayer(key: string, value: unknown): boolean {
  if (HIDDEN_LAYER_KEYS.has(key)) return true;
  if (value == null) return true;
  return false;
}

function normalizeLayerName(layerName: string): string {
  return layerName.trim().toLowerCase();
}

function layerTitle(layerName: string): string {
  return LAYER_TITLES[layerName] ?? humanizeFieldName(layerName);
}

function buildFieldLabel(name: string, value: string): string {
  const label = humanizeFieldName(name);
  if (!value) return label;
  return `${label}: ${value}`;
}

function stripLayerPrefix(fieldName: string, layerName: string): string {
  let result = fieldName;
  const dottedPrefix = `${layerName}.`;
  const underscoredPrefix = `${layerName}_`;
  while (result.toLowerCase().startsWith(dottedPrefix)) {
    result = result.slice(dottedPrefix.length);
  }
  while (result.toLowerCase().startsWith(underscoredPrefix)) {
    result = result.slice(underscoredPrefix.length);
  }
  return result;
}

function humanizeFieldName(name: string): string {
  const cleaned = name.replace(/\[(\d+)\]/g, "#$1");
  return cleaned
    .split(/[._\s]+/)
    .filter(Boolean)
    .map((part) => {
      const normalized = part.toLowerCase();
      if (TOKEN_LABELS[normalized]) {
        return TOKEN_LABELS[normalized];
      }
      if (/^#\d+$/.test(part)) {
        return part;
      }
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(" ");
}

function transportLayerTitle(proto: string): string {
  const normalized = proto.toLowerCase();
  return LAYER_TITLES[normalized] ?? proto;
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
  if (name === "tcp" || name === "udp" || name === "icmp" || name === "icmpv6" || name === "igmp") return layout.transportRange;
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

function resolveChildByteRange(_name: string, inheritedRange?: [number, number]): [number, number] | undefined {
  return inheritedRange;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatLeafValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map((item) => formatLeafValue(item)).filter(Boolean).join(", ");
  if (isRecord(value)) return "{...}";
  return String(value);
}

function toInteger(value: string): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

export const DEFAULT_PLUGIN_LOGS = [
  "[INFO] 插件引擎启动完成",
  "[INFO] 规则加载: 131 条",
  "[DEBUG] 等待数据流输入",
];
