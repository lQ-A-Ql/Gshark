export const PACKET_FILTER_POLL_INTERVAL_MS = 300;
export const PACKET_FILTER_POLL_TIMEOUT_MS = 10000;

export function normalizePacketFilterValue(value: string): string {
  return value.trim();
}

export function getPacketFilterWorkingStatus(filter: string): string {
  const normalized = normalizePacketFilterValue(filter);
  return normalized ? `正在应用过滤器: ${filter}` : "正在重置过滤器";
}

export function getPacketFilterPollingStatus(filter: string): string {
  const normalized = normalizePacketFilterValue(filter);
  return normalized ? `过滤器仍在后台扫描: ${filter}` : "正在重置过滤器";
}

export function getPacketFilterDoneStatus(filter: string): string {
  const normalized = normalizePacketFilterValue(filter);
  return normalized ? `过滤器已应用: ${filter}` : "过滤器已清空";
}
