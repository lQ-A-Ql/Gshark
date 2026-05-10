export function getPacketPageLoadErrorMessage(error: unknown): string {
  const detail = error instanceof Error && error.message.trim() ? error.message.trim() : "数据包读取失败";
  return `数据面读取失败: ${detail}`;
}

export function getPacketPageRetryStatus(filter: string): string {
  const trimmed = filter.trim();
  return trimmed ? `正在重新读取过滤结果: ${trimmed}` : "正在重新读取数据包首页";
}
