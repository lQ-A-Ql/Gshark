import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { normalizeCapturePathForCompare } from "./captureCommitStatus";

export type CapturePreloadConfirmPhase =
  | "idle"
  | "starting"
  | "waiting_for_packets"
  | "waiting_for_status"
  | "path_mismatch"
  | "status_failed"
  | "ready"
  | "failed";

export type CapturePreloadStatusTransport = "desktop-ipc" | "http-fallback" | "unknown";

export interface CapturePreloadDiagnostics {
  phase: CapturePreloadConfirmPhase;
  openedPath: string;
  normalizedOpenedPath: string;
  statusPath: string;
  normalizedStatusPath: string;
  statusPathMatches: boolean;
  statusHasCapture: boolean;
  statusPacketCount: number;
  pageTotal: number;
  pageItems: number;
  statusTransport: CapturePreloadStatusTransport;
  lastStatusError: string;
  lastPageError: string;
  statusConfirmDegraded: boolean;
  updatedAt: string;
}

interface CapturePreloadDiagnosticsInput {
  readonly phase: CapturePreloadConfirmPhase;
  readonly openedPath: string;
  readonly page?: PacketsPageResult | null;
  readonly status?: CaptureStatus | null;
  readonly statusTransport?: CapturePreloadStatusTransport;
  readonly lastStatusError?: string;
  readonly lastPageError?: string;
  readonly statusConfirmDegraded?: boolean;
  readonly now?: () => Date;
}

export function createCapturePreloadDiagnostics({
  phase,
  openedPath,
  page,
  status,
  statusTransport,
  lastStatusError = "",
  lastPageError = "",
  statusConfirmDegraded = false,
  now = () => new Date(),
}: CapturePreloadDiagnosticsInput): CapturePreloadDiagnostics {
  const statusPath = status?.filePath ?? "";
  const normalizedOpenedPath = normalizeCapturePathForCompare(openedPath);
  const normalizedStatusPath = normalizeCapturePathForCompare(statusPath);
  return {
    phase,
    openedPath,
    normalizedOpenedPath,
    statusPath,
    normalizedStatusPath,
    statusPathMatches: normalizedOpenedPath !== "" && normalizedOpenedPath === normalizedStatusPath,
    statusHasCapture: Boolean(status?.hasCapture),
    statusPacketCount: Number(status?.packetCount ?? 0),
    pageTotal: Number(page?.total ?? 0),
    pageItems: Number(page?.items.length ?? 0),
    statusTransport: statusTransport ?? status?.transport ?? "unknown",
    lastStatusError: lastStatusError || status?.transportError || "",
    lastPageError,
    statusConfirmDegraded,
    updatedAt: now().toISOString(),
  };
}

export function describePreloadError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }
  if (typeof error === "string" && error.trim()) {
    return error.trim();
  }
  return "未知错误";
}

export function describeCapturePreloadDiagnostics(diagnostics: CapturePreloadDiagnostics | null): string {
  if (!diagnostics) return "";
  if (diagnostics.lastPageError) {
    return `数据页确认失败：${diagnostics.lastPageError}`;
  }
  if (diagnostics.lastStatusError) {
    return `状态确认失败：${diagnostics.lastStatusError}`;
  }
  if (diagnostics.phase === "path_mismatch") {
    return `后端当前抓包与本次打开文件不一致：后端=${diagnostics.statusPath || "空"}，本次=${diagnostics.openedPath}`;
  }
  if (diagnostics.statusConfirmDegraded) {
    return "后端已完成解析，数据页已可读；状态端点暂未确认，已按首次加载兜底继续。";
  }
  if (diagnostics.phase === "waiting_for_status") {
    return "数据页已返回，正在确认后端当前抓包状态。";
  }
  if (diagnostics.phase === "waiting_for_packets") {
    return "正在等待首屏数据页返回。";
  }
  return "";
}
