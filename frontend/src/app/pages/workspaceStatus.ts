import type { CaptureTransactionStatus } from "../state/sentinelTypes";

export function shouldShowWorkspaceWelcome(hasOpenedCapture: boolean, captureTransaction: CaptureTransactionStatus): boolean {
  return !hasOpenedCapture && captureTransaction.phase !== "failed";
}

export function shouldShowWorkspaceOpenFailure(hasOpenedCapture: boolean, captureTransaction: CaptureTransactionStatus): boolean {
  return !hasOpenedCapture && captureTransaction.phase === "failed";
}

export function shouldShowWorkspaceSwitchFailureBanner(captureTransaction: CaptureTransactionStatus): boolean {
  return captureTransaction.phase === "failed" && captureTransaction.hasActiveCapture;
}

export function getWorkspaceFilterLoadingTitle(message: string, displayFilter: string): string {
  const trimmedMessage = message.trim();
  if (trimmedMessage.startsWith("正在应用过滤器")) return trimmedMessage;
  if (trimmedMessage.startsWith("正在重置过滤器")) return trimmedMessage;
  return displayFilter.trim() ? `正在扫描过滤结果: ${displayFilter.trim()}` : "正在恢复全部流量";
}

export function getWorkspaceFilterLoadingDetail(displayFilter: string): string {
  return displayFilter.trim()
    ? "旧页已清空，首屏命中结果返回前会在这里显示实时进度。"
    : "正在重新装载未过滤的数据包第一页。";
}

export function getWorkspaceFilterErrorMessage(message: string, displayFilter: string): string {
  const trimmedMessage = message.trim();
  if (!trimmedMessage || !displayFilter.trim()) return "";
  const normalized = trimmedMessage.toLowerCase();
  if (
    normalized.includes("filter")
    || normalized.includes("过滤")
    || normalized.includes("tshark")
    || normalized.includes("unexpected")
    || normalized.includes("invalid")
  ) {
    return trimmedMessage;
  }
  return "";
}
