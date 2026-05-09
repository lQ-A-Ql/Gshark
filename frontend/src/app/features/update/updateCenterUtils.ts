export function formatReleaseTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value || "未知";
  }
  return parsed.toLocaleString("zh-CN", { hour12: false });
}
