import { isOperationTimeoutError } from "../utils/asyncControl";

export type ToolRuntimeProbeState = "idle" | "probing" | "ready" | "failed";
export type ToolRuntimeProbeTransport = "desktop-ipc" | "http-fallback" | "unknown";

export function detectToolRuntimeProbeTransport(): ToolRuntimeProbeTransport {
  if (typeof window === "undefined") {
    return "unknown";
  }
  const desktopApp = (window as any)?.go?.main?.DesktopApp;
  return desktopApp?.GetToolRuntimeSnapshot ? "desktop-ipc" : "http-fallback";
}

export function describeToolRuntimeProbeError(error: unknown): string {
  if (isOperationTimeoutError(error)) {
    return `运行时组件探测超时（${error.timeoutMs}ms），后端可能仍在进行慢探测。`;
  }
  if (error instanceof Error && error.message.trim()) {
    return normalizeProbeErrorMessage(error.message);
  }
  return "运行时组件探测失败，请重试。";
}

export function toolRuntimeProbeStateText(state: ToolRuntimeProbeState): string {
  switch (state) {
    case "probing":
      return "探测中";
    case "ready":
      return "已就绪";
    case "failed":
      return "探测失败";
    default:
      return "等待探测";
  }
}

export function toolRuntimeProbeTransportText(transport: ToolRuntimeProbeTransport): string {
  switch (transport) {
    case "desktop-ipc":
      return "Wails IPC";
    case "http-fallback":
      return "HTTP fallback";
    default:
      return "未知链路";
  }
}

function normalizeProbeErrorMessage(message: string): string {
  const text = message.trim();
  if (!text) {
    return "运行时组件探测失败，请重试。";
  }
  if (text.toLowerCase() === "unauthorized" || text.includes("401")) {
    return "运行时组件探测鉴权失败：后端 token 不匹配或已过期，请重启 Wails dev 后重试。";
  }
  if (text.includes("actively refused") || text.includes("积极拒绝") || text.includes("Failed to fetch")) {
    return "运行时组件探测无法连接后端：请确认 127.0.0.1:17891 没有被旧进程或非兼容服务占用。";
  }
  return text;
}
