import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { normalizeCapturePathForCompare } from "./captureCommitStatus";

export type CapturePreloadConfirmPhase =
  | "idle"
  | "starting"
  | "backend_parsing"
  | "backend_committing"
  | "waiting_for_packets"
  | "waiting_for_status"
  | "path_mismatch"
  | "status_failed"
  | "backend_failed"
  | "committed_empty"
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
  pageTransport: CapturePreloadStatusTransport;
  statusTransport: CapturePreloadStatusTransport;
  lastStatusError: string;
  lastPageError: string;
  statusConfirmDegraded: boolean;
  loadRunId: number;
  loadPath: string;
  normalizedLoadPath: string;
  loadPathMatches: boolean;
  loadPhase: string;
  loadParserProfile: string;
  loadEstimatedTotal: number;
  loadProcessed: number;
  loadAccepted: number;
  loadStagedCount: number;
  loadLastError: string;
  enrichmentPhase: string;
  enrichmentProcessed: number;
  enrichmentUpdated: number;
  enrichmentLastError: string;
  updatedAt: string;
}

interface CapturePreloadDiagnosticsInput {
  readonly phase: CapturePreloadConfirmPhase;
  readonly openedPath: string;
  readonly page?: PacketsPageResult | null;
  readonly status?: CaptureStatus | null;
  readonly pageTransport?: CapturePreloadStatusTransport;
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
  pageTransport,
  statusTransport,
  lastStatusError = "",
  lastPageError = "",
  statusConfirmDegraded = false,
  now = () => new Date(),
}: CapturePreloadDiagnosticsInput): CapturePreloadDiagnostics {
  const statusPath = status?.filePath ?? "";
  const load = status?.load;
  const loadPath = load?.filePath ?? "";
  const normalizedOpenedPath = normalizeCapturePathForCompare(openedPath);
  const normalizedStatusPath = normalizeCapturePathForCompare(statusPath);
  const normalizedLoadPath = normalizeCapturePathForCompare(loadPath);
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
    pageTransport: pageTransport ?? page?.transport ?? "unknown",
    statusTransport: statusTransport ?? status?.transport ?? "unknown",
    lastStatusError: lastStatusError || status?.transportError || "",
    lastPageError: lastPageError || page?.transportError || "",
    statusConfirmDegraded,
    loadRunId: Number(load?.runId ?? 0),
    loadPath,
    normalizedLoadPath,
    loadPathMatches: normalizedOpenedPath !== "" && normalizedOpenedPath === normalizedLoadPath,
    loadPhase: load?.phase ?? "",
    loadParserProfile: load?.parserProfile ?? "",
    loadEstimatedTotal: Number(load?.estimatedTotal ?? 0),
    loadProcessed: Number(load?.processed ?? 0),
    loadAccepted: Number(load?.accepted ?? 0),
    loadStagedCount: Number(load?.stagedCount ?? 0),
    loadLastError: load?.lastError ?? "",
    enrichmentPhase: load?.enrichment?.phase ?? "",
    enrichmentProcessed: Number(load?.enrichment?.processed ?? 0),
    enrichmentUpdated: Number(load?.enrichment?.updated ?? 0),
    enrichmentLastError: load?.enrichment?.lastError ?? "",
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
  if (diagnostics.phase === "backend_failed") {
    return `后端解析失败：${diagnostics.loadLastError || "未知错误"}`;
  }
  if (diagnostics.phase === "backend_committing") {
    return "后端已完成解析，正在提交首屏数据。";
  }
  if (diagnostics.phase === "backend_parsing") {
    const total = diagnostics.loadEstimatedTotal > 0 ? `/${diagnostics.loadEstimatedTotal}` : "";
    return `后端正在解析，尚未提交首屏数据：已处理 ${diagnostics.loadProcessed}${total}，入库 ${diagnostics.loadAccepted}。`;
  }
  if (diagnostics.phase === "committed_empty") {
    return "后端已提交抓包，但首屏数据仍为空，请检查过滤条件或入库状态。";
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
