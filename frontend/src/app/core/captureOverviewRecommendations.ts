import type { TrafficBucket } from "./types";
import { INDUSTRIAL_FILTER, MEDIA_FILTER, VEHICLE_FILTER } from "./captureOverviewFilters";
import type { CaptureOverviewCounts, CaptureOverviewInput, CaptureRecommendation } from "./captureOverviewTypes";

export function buildRecommendations(
  input: CaptureOverviewInput,
  counts: CaptureOverviewCounts,
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
      summary:
        counts.httpStreams > 0
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
    (counts.tcpStreams > 0 ? 18 : 0) + (counts.udpStreams > 0 ? 12 : 0) + (counts.suspicious > 0 ? 10 : 0);
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
