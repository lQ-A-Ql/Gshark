import type { CaptureOverviewCounts, CaptureOverviewInput } from "./captureOverviewTypes";

export function buildCaptureOverviewCounts(input: CaptureOverviewInput): CaptureOverviewCounts {
  return {
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
}
