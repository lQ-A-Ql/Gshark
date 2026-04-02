import type {
  ExtractedObject,
  GlobalTrafficStats,
  IndustrialAnalysis,
  MediaAnalysis,
  Packet,
  ThreatHit,
  TrafficBucket,
  USBAnalysis,
  VehicleAnalysis,
} from "./types";

export type CaptureModuleKey = "web" | "industrial" | "vehicle" | "usb" | "media" | "payload";

export interface CaptureQuickFilter {
  label: string;
  filter: string;
  reason: string;
}

export interface CaptureRecommendation {
  key: CaptureModuleKey;
  label: string;
  route: string;
  summary: string;
  score: number;
  filter?: string;
}

export interface CaptureOverviewSnapshot {
  headline: string;
  summary: string;
  topProtocols: TrafficBucket[];
  quickFilters: CaptureQuickFilter[];
  recommendations: CaptureRecommendation[];
  suspiciousHits: ThreatHit[];
}

export interface CaptureOverviewInput {
  stats: GlobalTrafficStats | null;
  packets: Packet[];
  threatHits: ThreatHit[];
  extractedObjects: ExtractedObject[];
  streamIds: { http: number[]; tcp: number[]; udp: number[] };
  industrial: IndustrialAnalysis | null;
  vehicle: VehicleAnalysis | null;
  media: MediaAnalysis | null;
  usb: USBAnalysis | null;
}

const INDUSTRIAL_FILTER = "modbus or s7comm or dnp3 or cip or bacnet or iec104 or opcua or pn_rt";
const VEHICLE_FILTER = "can or j1939 or doip or uds";
const MEDIA_FILTER = "rtp or rtcp or sip or sdp";

export function buildCaptureOverview(input: CaptureOverviewInput): CaptureOverviewSnapshot {
  const topProtocols = pickTopProtocols(input.stats, input.packets);
  const suspiciousHits = [...input.threatHits]
    .sort((a, b) => threatLevelRank(b.level) - threatLevelRank(a.level) || a.packetId - b.packetId)
    .slice(0, 5);

  const counts = {
    suspicious: input.threatHits.length,
    highRisk: input.threatHits.filter((hit) => hit.level === "critical" || hit.level === "high").length,
    httpStreams: input.streamIds.http.length,
    tcpStreams: input.streamIds.tcp.length,
    udpStreams: input.streamIds.udp.length,
    objects: input.extractedObjects.length,
    industrial: input.industrial?.totalIndustrialPackets ?? 0,
    vehicle: input.vehicle?.totalVehiclePackets ?? 0,
    usb: input.usb?.totalUSBPackets ?? 0,
    media: input.media?.totalMediaPackets ?? 0,
  };

  const recommendations = buildRecommendations(input, counts, topProtocols);
  const dominant = recommendations[0];
  const protocolSummary = topProtocols.map((item) => `${item.label} ${item.count}`).join(" / ");

  let headline = "先从全局流量分布入手";
  let summary = protocolSummary ? `当前更像通用网络流量，首屏可先看 ${protocolSummary}。` : "当前抓包已可进入主工作区进行协议、流和 payload 联动分析。";

  if (counts.highRisk > 0) {
    headline = `优先处理 ${counts.highRisk} 条高危命中`;
    summary = `已命中 ${counts.suspicious} 条可疑流量，建议先定位数据包，再进入对应流追踪与 payload 解码。`;
  } else if (counts.suspicious > 0) {
    headline = `已发现 ${counts.suspicious} 条可疑线索`;
    summary = "可以先打开威胁狩猎命中，再按包号回到主工作区验证上下文。";
  } else if (dominant && dominant.score >= 50) {
    headline = `当前抓包偏向${dominant.label}`;
    summary = dominant.summary;
  }

  return {
    headline,
    summary,
    topProtocols,
    quickFilters: buildQuickFilters(input, counts, topProtocols),
    recommendations,
    suspiciousHits,
  };
}

function buildRecommendations(
  input: CaptureOverviewInput,
  counts: {
    suspicious: number;
    highRisk: number;
    httpStreams: number;
    tcpStreams: number;
    udpStreams: number;
    objects: number;
    industrial: number;
    vehicle: number;
    usb: number;
    media: number;
  },
  topProtocols: TrafficBucket[],
): CaptureRecommendation[] {
  const topLabels = new Set(topProtocols.map((item) => item.label.toUpperCase()));
  const recommendations: CaptureRecommendation[] = [];

  const webScore =
    (counts.httpStreams > 0 ? 38 : 0) +
    (counts.objects > 0 ? 10 : 0) +
    (topLabels.has("HTTP") ? 14 : 0) +
    (topLabels.has("HTTPS") || topLabels.has("TLS") || topLabels.has("TLSV1.3") ? 14 : 0) +
    (topLabels.has("DNS") ? 6 : 0) +
    (input.threatHits.some((hit) => hit.category === "OWASP" || hit.category === "Sensitive") ? 16 : 0);
  if (webScore > 0) {
    recommendations.push({
      key: "web",
      label: "Web / 通用会话",
      route: counts.httpStreams > 0 ? "/http-stream" : "/",
      summary: counts.httpStreams > 0
        ? `检测到 ${counts.httpStreams} 条 HTTP 会话，适合先看请求响应与 payload 快速解码。`
        : "当前抓包包含明显的 Web/TLS/DNS 特征，适合从工作区和过滤器切入。",
      score: webScore,
      filter: "http or tls or dns",
    });
  }

  if (counts.industrial > 0) {
    recommendations.push({
      key: "industrial",
      label: "工控流量",
      route: "/industrial-analysis",
      summary: `识别到 ${counts.industrial.toLocaleString()} 个工控相关包，建议直接进入工控分析页查看协议和事务。`,
      score: 60 + Math.min(30, Math.floor(counts.industrial / 20)),
      filter: INDUSTRIAL_FILTER,
    });
  }

  if (counts.vehicle > 0) {
    recommendations.push({
      key: "vehicle",
      label: "车机流量",
      route: "/vehicle-analysis",
      summary: `识别到 ${counts.vehicle.toLocaleString()} 个车机相关包，可优先查看 CAN / DoIP / UDS 线索。`,
      score: 60 + Math.min(28, Math.floor(counts.vehicle / 12)),
      filter: VEHICLE_FILTER,
    });
  }

  if (counts.usb > 0) {
    recommendations.push({
      key: "usb",
      label: "USB 流量",
      route: "/usb-analysis",
      summary: `识别到 ${counts.usb.toLocaleString()} 个 USB 相关包，可直接查看键鼠回放和设备行为。`,
      score: 56 + Math.min(24, Math.floor(counts.usb / 12)),
      filter: "usb",
    });
  }

  if (counts.media > 0) {
    recommendations.push({
      key: "media",
      label: "RTP / 媒体流",
      route: "/media-analysis",
      summary: `识别到 ${counts.media.toLocaleString()} 个媒体相关包，建议直接进入媒体分析页确认会话与导出物。`,
      score: 54 + Math.min(24, Math.floor(counts.media / 10)),
      filter: MEDIA_FILTER,
    });
  }

  const payloadScore =
    (counts.tcpStreams > 0 ? 18 : 0) +
    (counts.udpStreams > 0 ? 12 : 0) +
    (counts.suspicious > 0 ? 10 : 0);
  if (payloadScore > 0) {
    recommendations.push({
      key: "payload",
      label: "原始 Payload",
      route: counts.tcpStreams >= counts.udpStreams ? "/tcp-stream" : "/udp-stream",
      summary: "当前抓包存在可跟踪原始流，适合结合选中数据包直接做 Base64 / WebShell payload 解码。",
      score: payloadScore,
      filter: counts.tcpStreams >= counts.udpStreams ? "tcp" : "udp",
    });
  }

  return recommendations
    .sort((a, b) => b.score - a.score || a.label.localeCompare(b.label, "zh-CN"))
    .slice(0, 5);
}

function buildQuickFilters(
  input: CaptureOverviewInput,
  counts: {
    suspicious: number;
    highRisk: number;
    httpStreams: number;
    tcpStreams: number;
    udpStreams: number;
    objects: number;
    industrial: number;
    vehicle: number;
    usb: number;
    media: number;
  },
  topProtocols: TrafficBucket[],
): CaptureQuickFilter[] {
  const suggestions: CaptureQuickFilter[] = [];

  if (counts.highRisk > 0 || counts.suspicious > 0) {
    suggestions.push({
      label: "异常 TCP",
      filter: "tcp.analysis.flags or tcp.flags.reset == 1",
      reason: "快速筛出重传、RST、乱序等异常会话",
    });
  }

  if (counts.httpStreams > 0) {
    suggestions.push({
      label: "HTTP / TLS",
      filter: "http or tls",
      reason: "快速回到 Web 会话与证书、请求、响应相关包",
    });
  }

  if (counts.industrial > 0) {
    suggestions.push({
      label: "工控协议",
      filter: INDUSTRIAL_FILTER,
      reason: "聚焦工控请求、控制命令与异常响应",
    });
  }

  if (counts.vehicle > 0) {
    suggestions.push({
      label: "车机协议",
      filter: VEHICLE_FILTER,
      reason: "聚焦 CAN、J1939、DoIP、UDS",
    });
  }

  if (counts.usb > 0) {
    suggestions.push({
      label: "USB",
      filter: "usb",
      reason: "聚焦 HID、控制传输与设备行为",
    });
  }

  if (counts.media > 0) {
    suggestions.push({
      label: "RTP / SIP",
      filter: MEDIA_FILTER,
      reason: "快速进入媒体相关信令与 RTP 数据",
    });
  }

  const dominantProtocol = topProtocols[0]?.label?.toUpperCase() ?? "";
  if (dominantProtocol && !suggestions.some((item) => item.label.toUpperCase().includes(dominantProtocol))) {
    const protocolFilter = filterForProtocol(dominantProtocol);
    if (protocolFilter) {
      suggestions.push({
        label: dominantProtocol,
        filter: protocolFilter,
        reason: "按当前主协议回看上下文",
      });
    }
  }

  if (!suggestions.some((item) => item.filter === "frame.len > 1000")) {
    suggestions.push({
      label: "大包",
      filter: "frame.len > 1000",
      reason: "快速观察大流量传输、文件、媒体或隧道特征",
    });
  }

  return dedupeQuickFilters(suggestions).slice(0, 6);
}

function pickTopProtocols(stats: GlobalTrafficStats | null, packets: Packet[]): TrafficBucket[] {
  if (stats && Array.isArray(stats.protocolDist) && stats.protocolDist.length > 0) {
    return stats.protocolDist.slice(0, 4);
  }

  const counts = new Map<string, number>();
  for (const packet of packets) {
    const label = String(packet.displayProtocol || packet.proto || "OTHER").trim().toUpperCase();
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 4);
}

function dedupeQuickFilters(items: CaptureQuickFilter[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.label}::${item.filter}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function threatLevelRank(level: ThreatHit["level"]) {
  if (level === "critical") return 4;
  if (level === "high") return 3;
  if (level === "medium") return 2;
  return 1;
}

function filterForProtocol(label: string) {
  switch (label) {
    case "HTTP":
      return "http";
    case "HTTPS":
    case "TLS":
    case "TLSV1.2":
    case "TLSV1.3":
      return "tls";
    case "DNS":
      return "dns";
    case "TCP":
      return "tcp";
    case "UDP":
      return "udp";
    case "ARP":
      return "arp";
    case "ICMP":
      return "icmp";
    case "ICMPV6":
      return "icmpv6";
    case "USB":
      return "usb";
    case "MODBUS":
    case "S7COMM":
    case "DNP3":
    case "CIP":
    case "BACNET":
    case "IEC104":
    case "OPCUA":
    case "PN_RT":
      return INDUSTRIAL_FILTER;
    case "CAN":
    case "J1939":
    case "DOIP":
    case "UDS":
      return VEHICLE_FILTER;
    case "RTP":
    case "RTCP":
    case "SIP":
    case "SDP":
      return MEDIA_FILTER;
    default:
      return "";
  }
}
