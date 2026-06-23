import { isOperationTimeoutError } from "../utils/asyncControl";

export type ToolRuntimeProbeState =
  | "idle"
  | "probing"
  | "probing_fast"
  | "partial"
  | "probing_full"
  | "ready"
  | "timeout_background"
  | "failed";
export type ToolRuntimeProbeTransport = "desktop-ipc" | "browser-dev" | "unknown";
type RuntimeSnapshotTransport = ToolRuntimeProbeTransport | string | null | undefined;

type ToolRuntimeProbeWindow = Window & {
  go?: {
    main?: {
      DesktopApp?: {
        GetToolRuntimeSnapshotFast?: unknown;
        GetToolRuntimeSnapshot?: unknown;
      };
    };
  };
};

export function detectToolRuntimeProbeTransport(): ToolRuntimeProbeTransport {
  if (typeof window === "undefined") {
    return "unknown";
  }
  const desktopApp = (window as ToolRuntimeProbeWindow).go?.main?.DesktopApp;
  return desktopApp?.GetToolRuntimeSnapshotFast || desktopApp?.GetToolRuntimeSnapshot ? "desktop-ipc" : "browser-dev";
}

export function normalizeToolRuntimeProbeTransport(transport: RuntimeSnapshotTransport): ToolRuntimeProbeTransport {
  if (transport === "desktop-ipc" || transport === "browser-dev" || transport === "unknown") {
    return transport;
  }
  return typeof transport === "string" && transport.trim() ? "browser-dev" : detectToolRuntimeProbeTransport();
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
    case "probing_fast":
      return "探测中";
    case "partial":
      return "快速状态已就绪";
    case "probing_full":
      return "完整探测中";
    case "ready":
      return "已就绪";
    case "timeout_background":
      return "后台探测中";
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
    case "browser-dev":
      return "Browser dev";
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
    return "运行时组件探测无法连接后端：请确认本地开发后端没有被旧进程或非兼容服务占用。";
  }
  return text;
}
