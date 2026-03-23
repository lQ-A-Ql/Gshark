import type {
  BinaryStream,
  ExtractedObject,
  HttpStream,
  Packet,
  PluginItem,
  Protocol,
  ProtocolTreeNode,
  ThreatHit,
  ThreatLevel,
} from "./types";

const IPS = ["192.168.1.10", "10.0.0.5", "10.0.0.22", "172.16.33.8", "8.8.8.8"];
const METHODS = ["GET", "POST", "PUT"];
const HTTP_PATHS = ["/", "/login", "/api/v1/upload", "/admin", "/search?q=flag"];

function seededRandom(seed: number) {
  const x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
}

function pick<T>(arr: T[], seed: number): T {
  return arr[Math.floor(seededRandom(seed) * arr.length)];
}

function formatTime(i: number): string {
  return (i * 0.00123).toFixed(6);
}

function payloadFor(i: number, proto: Protocol): string {
  if (proto === "HTTP") {
    const method = pick(METHODS, i + 7);
    const path = pick(HTTP_PATHS, i + 13);
    if (method === "POST") {
      const suspicious = i % 97 === 0 ? "whoami && cat /etc/passwd" : "normal_upload";
      return `${method} ${path} HTTP/1.1\nHost: target.local\n\n${suspicious}`;
    }
    if (path.includes("search")) {
      return `${method} ${path} HTTP/1.1\nHost: target.local\n\nq=' OR '1'='1 --`;
    }
    return `${method} ${path} HTTP/1.1\nHost: target.local\n\n`;
  }

  if (proto === "DNS") {
    return i % 33 === 0
      ? "TXT exfil.chunk.001.example"
      : "A www.example.com";
  }

  if (proto === "SSHv2") {
    return i % 50 === 0 ? "Encrypted packet (len=512)" : "SSH key exchange";
  }

  if (proto === "TLS" || proto === "HTTPS") {
    return i % 42 === 0 ? "TLS Application Data" : "Client Hello";
  }

  return i % 71 === 0 ? "flag{network_forensics_master}" : "binary data";
}

export function generatePackets(count = 4000): Packet[] {
  const packets: Packet[] = [];

  for (let i = 1; i <= count; i += 1) {
    const proto = pick<Protocol>(["TCP", "UDP", "HTTP", "DNS", "SSHv2", "TLS"], i + 3);
    const src = pick(IPS, i + 11);
    let dst = pick(IPS, i + 17);
    if (src === dst) dst = "10.0.0.5";

    const srcPort = proto === "HTTP" ? 50000 + (i % 1000) : 1000 + (i % 50000);
    const dstPort =
      proto === "HTTP"
        ? 80
        : proto === "DNS"
          ? 53
          : proto === "SSHv2"
            ? 22
            : proto === "TLS"
              ? 443
              : 9000 + (i % 2000);

    const payload = payloadFor(i, proto);
    const isHttp = proto === "HTTP";
    const method = isHttp ? payload.split(" ")[0] : undefined;
    const statusCode = isHttp && i % 7 === 0 ? 404 : isHttp && i % 11 === 0 ? 403 : isHttp ? 200 : undefined;

    packets.push({
      id: i,
      time: formatTime(i),
      src,
      srcPort,
      dst,
      dstPort,
      proto,
      length: 60 + (i % 1400),
      info: isHttp
        ? `${method} ${payload.split(" ")[1]} HTTP/1.1`
        : `${srcPort} > ${dstPort} ${proto}`,
      payload,
      statusCode,
      method,
      streamId: Math.floor(i / 20) + 1,
    });
  }

  return packets;
}

function parseToken(token: string, packet: Packet): boolean {
  const t = token.trim().toLowerCase();
  if (!t) return true;

  if (t.startsWith("ip.src ==")) {
    const value = token.split("==")[1]?.trim().replaceAll('"', "");
    return packet.src === value;
  }
  if (t.startsWith("ip.dst ==")) {
    const value = token.split("==")[1]?.trim().replaceAll('"', "");
    return packet.dst === value;
  }
  if (t.startsWith("tcp.port ==") || t.startsWith("udp.port ==") || t.startsWith("port ==")) {
    const value = Number(token.split("==")[1]?.trim());
    return packet.srcPort === value || packet.dstPort === value;
  }
  if (t === "http") return packet.proto === "HTTP";
  if (t === "tcp") return packet.proto === "TCP";
  if (t === "udp") return packet.proto === "UDP";
  if (t === "dns") return packet.proto === "DNS";
  if (t === "tls" || t === "https") return packet.proto === "TLS" || packet.proto === "HTTPS";
  if (t.startsWith("http.request.method ==")) {
    const value = token.split("==")[1]?.trim().replaceAll('"', "").toUpperCase();
    return packet.method?.toUpperCase() === value;
  }
  if (t.startsWith("http.response.code ==")) {
    const value = Number(token.split("==")[1]?.trim());
    return packet.statusCode === value;
  }

  return (
    packet.info.toLowerCase().includes(t) ||
    packet.payload.toLowerCase().includes(t) ||
    packet.src.includes(t) ||
    packet.dst.includes(t)
  );
}

export function applyDisplayFilter(packets: Packet[], filter: string): Packet[] {
  if (!filter.trim()) return packets;

  const orParts = filter
    .split(/\s+or\s+/i)
    .map((x) => x.trim())
    .filter(Boolean);

  return packets.filter((packet) =>
    orParts.some((part) => {
      const andParts = part
        .split(/\s+and\s+/i)
        .map((x) => x.trim())
        .filter(Boolean);
      return andParts.every((token) => parseToken(token, packet));
    }),
  );
}

function levelByRule(rule: string): ThreatLevel {
  if (rule.includes("RCE") || rule.includes("WebShell")) return "critical";
  if (rule.includes("SQL") || rule.includes("XSS")) return "high";
  if (rule.includes("敏感")) return "medium";
  return "low";
}

export function detectThreats(packets: Packet[]): ThreatHit[] {
  const rules: { name: string; category: ThreatHit["category"]; regex: RegExp }[] = [
    { name: "SQL 注入", category: "OWASP", regex: /\bunion\b|\bselect\b|'\s+or\s+'1'='1/i },
    { name: "XSS", category: "OWASP", regex: /<script|onerror=|javascript:/i },
    { name: "命令执行 RCE", category: "OWASP", regex: /whoami|\/etc\/passwd|cmd\.exe|powershell/i },
    { name: "Flag 嗅探", category: "CTF", regex: /flag\{|ctf\{/i },
    { name: "敏感凭证", category: "Sensitive", regex: /AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\./i },
  ];

  const hits: ThreatHit[] = [];
  let seq = 1;

  for (const packet of packets) {
    const text = `${packet.info}\n${packet.payload}`;
    for (const rule of rules) {
      const m = text.match(rule.regex);
      if (!m) continue;

      hits.push({
        id: seq,
        packetId: packet.id,
        category: rule.category,
        rule: rule.name,
        level: levelByRule(rule.name),
        preview: text.slice(0, 120),
        match: m[0],
      });
      seq += 1;
    }
  }

  const bySource403404 = new Map<string, number>();
  for (const p of packets) {
    if (p.statusCode === 403 || p.statusCode === 404) {
      bySource403404.set(p.src, (bySource403404.get(p.src) ?? 0) + 1);
    }
  }

  for (const [src, count] of bySource403404) {
    if (count < 6) continue;
    hits.push({
      id: seq,
      packetId: 1,
      category: "Anomaly",
      rule: "异常扫描行为",
      level: "medium",
      preview: `源 IP ${src} 在短时窗口触发 ${count} 次 403/404`,
      match: `${src} (${count})`,
    });
    seq += 1;
  }

  return hits;
}

export function extractObjects(packets: Packet[]): ExtractedObject[] {
  const objects: ExtractedObject[] = [];
  let idx = 1;

  for (const packet of packets) {
    if (packet.proto !== "HTTP") continue;
    const lower = packet.payload.toLowerCase();
    if (!lower.includes("upload") && !lower.includes("http/1.1")) continue;

    const maybeName =
      /filename="([^"]+)"/i.exec(packet.payload)?.[1] ??
      (packet.info.includes("/admin") ? "admin-panel.html" : `object-${packet.id}.bin`);
    const mime =
      maybeName.endsWith(".png") || maybeName.endsWith(".jpg")
        ? "image/png"
        : maybeName.endsWith(".zip")
          ? "application/zip"
          : maybeName.endsWith(".html")
            ? "text/html"
            : "application/octet-stream";

    objects.push({
      id: idx,
      packetId: packet.id,
      name: maybeName,
      sizeBytes: 512 + (packet.length * 13) % 4_000_000,
      mime,
      source: "HTTP",
    });
    idx += 1;

    if (objects.length >= 80) break;
  }

  return objects;
}

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

export function buildHttpStream(packets: Packet[]): HttpStream {
  const first = packets.find((p) => p.proto === "HTTP") ?? packets[0];
  const req = packets.find((p) => p.proto === "HTTP" && p.method === "POST") ?? first;
  const resCode = req?.statusCode ?? 200;

  const request = `${req.method ?? "GET"} ${req.info.split(" ")[1] ?? "/"} HTTP/1.1\nHost: target.local\nUser-Agent: GShark\n\n${req.payload}`;
  const response = `HTTP/1.1 ${resCode} ${resCode === 200 ? "OK" : "NOT FOUND"}\nServer: nginx\nContent-Type: application/json\n\n{\n  \"status\": \"ok\",\n  \"packet\": ${req.id}\n}`;

  return {
    id: req.streamId ?? 1,
    client: `${req.src}:${req.srcPort}`,
    server: `${req.dst}:${req.dstPort}`,
    request,
    response,
    chunks: packets
      .filter((p) => p.proto === "HTTP")
      .slice(0, 200)
      .map((p) => ({
        packetId: p.id,
        direction: p.src === req.src && p.srcPort === req.srcPort ? "client" : "server",
        body: p.payload,
      })),
  };
}

function mapStream(p: Packet): "client" | "server" {
  return p.id % 2 === 0 ? "server" : "client";
}

export function buildBinaryStream(packets: Packet[], protocol: "TCP" | "UDP"): BinaryStream {
  const picked = packets.filter((p) => p.proto === protocol).slice(0, 40);
  const first = picked[0] ?? packets[0];

  return {
    id: first.streamId ?? 1,
    protocol,
    from: `${first.src}:${first.srcPort}`,
    to: `${first.dst}:${first.dstPort}`,
    chunks: picked.map((p) => ({
      packetId: p.id,
      direction: mapStream(p),
      body: p.payload,
    })),
  };
}

export const DEFAULT_PLUGINS: PluginItem[] = [
  { id: 1, name: "冰蝎/哥斯拉 WebShell 解密引擎", enabled: true, version: "2.1.0", author: "GShark-Team", tag: "解密" },
  { id: 2, name: "SQLMap 扫描器识别器", enabled: true, version: "1.4.3", author: "Community", tag: "检测" },
  { id: 3, name: "自定义协议解析: IoT", enabled: false, version: "0.9.0", author: "User-Local", tag: "解析" },
  { id: 4, name: "Cobalt Strike Beacon 提取器", enabled: true, version: "3.0.1", author: "GShark-Team", tag: "提取" },
];

export const DEFAULT_PLUGIN_LOGS = [
  "[INFO] 插件引擎启动完成",
  "[INFO] 规则加载: 131 条",
  "[DEBUG] 等待数据流输入",
];
