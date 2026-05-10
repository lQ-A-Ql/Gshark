import type { TrafficBucket } from "./types";
import { filterForProtocol, INDUSTRIAL_FILTER, MEDIA_FILTER, VEHICLE_FILTER } from "./captureOverviewFilters";
import type { CaptureOverviewCounts, CaptureQuickFilter } from "./captureOverviewTypes";

export function buildQuickFilters(
  counts: CaptureOverviewCounts,
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
