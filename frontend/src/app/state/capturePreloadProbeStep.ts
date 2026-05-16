import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { isCommittedCaptureStatusForPath, normalizeCapturePathForCompare } from "./captureCommitStatus";
import {
  createCapturePreloadDiagnostics,
  describePreloadError,
  type CapturePreloadConfirmPhase,
  type CapturePreloadDiagnostics,
} from "./capturePreloadDiagnostics";
import { getCaptureEmptyParseError, getCapturePreloadTimeoutError } from "./capturePreloadStatus";
import type { OpenedCapture } from "./captureOpenState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;
type CapturePreloadFirstPage = Pick<PacketsPageResult, "items" | "total" | "hasMore">;

export interface ProbeResult {
  readonly stale: boolean;
  readonly page: PacketsPageResult | null;
  readonly pageError: string;
  readonly captureStatus: CaptureStatus | null;
  readonly statusError: string;
  readonly activeCaptureConfirmed: boolean;
}

export function isActiveLoadForOpenedCapture(status: CaptureStatus | null, openedPath: string): boolean {
  const loadPath = status?.load?.filePath ?? "";
  return (
    normalizeCapturePathForCompare(openedPath) !== "" &&
    normalizeCapturePathForCompare(openedPath) === normalizeCapturePathForCompare(loadPath) &&
    Boolean(status?.load?.phase)
  );
}

export interface ProbePageState {
  readonly firstPageLoaded: boolean;
  readonly candidateFirstPage: CapturePreloadFirstPage | null;
  readonly validatedFirstPage: CapturePreloadFirstPage | null;
}

export function applyProbePageState({
  page,
  activeCaptureConfirmed,
  state,
  preloadProcessedRef,
  preloadTotalRef,
  setTotalPackets,
  setPreloadProcessed,
}: {
  readonly page: PacketsPageResult | null;
  readonly activeCaptureConfirmed: boolean;
  readonly state: ProbePageState;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly setTotalPackets: Setter<number>;
  readonly setPreloadProcessed: Setter<number>;
}): ProbePageState {
  if (!page || page.total <= 0) return state;
  setTotalPackets(page.total);
  if (preloadTotalRef.current <= 0) {
    setPreloadProcessed(page.total);
    preloadProcessedRef.current = page.total;
  }
  const candidateFirstPage = state.candidateFirstPage ?? toFirstPage(page);
  if (state.firstPageLoaded || !activeCaptureConfirmed) {
    return { ...state, candidateFirstPage };
  }
  return {
    firstPageLoaded: true,
    candidateFirstPage,
    validatedFirstPage: toFirstPage(page),
  };
}

export async function probeCapturePage({
  opened,
  filter,
  limit,
  captureSeq,
  captureSeqRef,
  captureTaskScopeRef,
  listPacketsPage,
  getCaptureStatus,
}: {
  readonly opened: OpenedCapture;
  readonly filter: string;
  readonly limit: number;
  readonly captureSeq: number;
  readonly captureSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter?: string,
    signal?: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly getCaptureStatus: (signal?: AbortSignal) => Promise<CaptureStatus>;
}): Promise<ProbeResult> {
  const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
  try {
    const [pageResult, statusResult] = await Promise.allSettled([
      listPacketsPage(0, limit, filter, probeTask.signal),
      getCaptureStatus(probeTask.signal),
    ]);
    if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) {
      return emptyStaleProbe();
    }
    const page = pageResult.status === "fulfilled" ? pageResult.value : null;
    const captureStatus = statusResult.status === "fulfilled" ? statusResult.value : null;
    return {
      stale: false,
      page,
      pageError: pageResult.status === "rejected" ? describePreloadError(pageResult.reason) : "",
      captureStatus,
      statusError: statusResult.status === "rejected" ? describePreloadError(statusResult.reason) : "",
      activeCaptureConfirmed: isCommittedCaptureStatusForPath(captureStatus, opened.filePath),
    };
  } finally {
    probeTask.finish();
  }
}

export function toFirstPage(page: PacketsPageResult): CapturePreloadFirstPage {
  return {
    items: page.items,
    total: page.total,
    hasMore: page.hasMore,
  };
}

export function publishDiagnostics({
  opened,
  probe,
  phase,
  statusConfirmDegraded = false,
  onDiagnostics,
}: {
  readonly opened: OpenedCapture;
  readonly probe: ProbeResult;
  readonly phase: CapturePreloadConfirmPhase;
  readonly statusConfirmDegraded?: boolean;
  readonly onDiagnostics?: (diagnostics: CapturePreloadDiagnostics) => void;
}): void {
  if (!onDiagnostics) return;
  onDiagnostics(
    createCapturePreloadDiagnostics({
      phase,
      openedPath: opened.filePath,
      page: probe.page,
      status: probe.captureStatus,
      statusTransport: probe.captureStatus?.transport,
      pageTransport: probe.page?.transport,
      lastStatusError: probe.statusError,
      lastPageError: probe.pageError,
      statusConfirmDegraded,
    }),
  );
}

export function publishProbeDiagnostics({
  opened,
  probe,
  activeCaptureConfirmed,
  firstPageLoaded,
  onDiagnostics,
}: {
  readonly opened: OpenedCapture;
  readonly probe: ProbeResult;
  readonly activeCaptureConfirmed: boolean;
  readonly firstPageLoaded: boolean;
  readonly onDiagnostics?: (diagnostics: CapturePreloadDiagnostics) => void;
}): void {
  publishDiagnostics({
    opened,
    probe,
    phase: getProbePhase(
      probe,
      activeCaptureConfirmed,
      firstPageLoaded,
      isActiveLoadForOpenedCapture(probe.captureStatus, opened.filePath),
    ),
    onDiagnostics,
  });
}

export function publishReadyDiagnostics(
  opened: OpenedCapture,
  probe: ProbeResult,
  onDiagnostics?: (diagnostics: CapturePreloadDiagnostics) => void,
  statusConfirmDegraded = false,
): void {
  publishDiagnostics({ opened, probe, phase: "ready", statusConfirmDegraded, onDiagnostics });
}

export function getProbePhase(
  probe: ProbeResult,
  activeCaptureConfirmed: boolean,
  firstPageLoaded: boolean,
  activeLoadMatches = false,
): CapturePreloadConfirmPhase {
  const loadPhase = probe.captureStatus?.load?.phase;
  if (activeLoadMatches && (loadPhase === "failed" || loadPhase === "canceled")) return "backend_failed";
  if (activeLoadMatches && loadPhase === "committing") return "backend_committing";
  if (
    activeLoadMatches &&
    (loadPhase === "starting" || loadPhase === "counting" || loadPhase === "parsing") &&
    (!probe.page || probe.page.total <= 0)
  ) {
    return "backend_parsing";
  }
  if (probe.pageError) return "waiting_for_packets";
  if (probe.captureStatus?.hasCapture && probe.captureStatus.packetCount > 0 && probe.page?.total === 0) {
    return "committed_empty";
  }
  if (!probe.page || probe.page.total <= 0 || !firstPageLoaded) return "waiting_for_packets";
  if (probe.statusError) return "status_failed";
  if (!probe.captureStatus?.hasCapture || probe.captureStatus.packetCount <= 0) return "waiting_for_status";
  if (!activeCaptureConfirmed) return "path_mismatch";
  return "ready";
}

export function getPathMismatchError(opened: OpenedCapture, status: CaptureStatus): string {
  return [
    "后端当前抓包与本次打开文件不一致",
    `本次打开: ${opened.filePath}`,
    `后端状态: ${status.filePath || "空"}`,
    `后端包数: ${status.packetCount}`,
  ].join("；");
}

export function canUseDegradedFirstPage({
  hadActiveCapture,
  parseFinished,
  parseError,
  candidateFirstPage,
  probe,
}: {
  readonly hadActiveCapture: boolean;
  readonly parseFinished: boolean;
  readonly parseError: string;
  readonly candidateFirstPage: CapturePreloadFirstPage | null;
  readonly probe: ProbeResult;
}): boolean {
  return (
    !hadActiveCapture &&
    parseFinished &&
    !parseError &&
    Boolean(candidateFirstPage && candidateFirstPage.total > 0) &&
    Boolean(probe.statusError)
  );
}

export function getParseFinishedProbeError({
  opened,
  probe,
  activeCaptureConfirmed,
  parseError,
}: {
  readonly opened: OpenedCapture;
  readonly probe: ProbeResult;
  readonly activeCaptureConfirmed: boolean;
  readonly parseError: string;
}): string {
  if (probe.page?.total === 0) return getCaptureEmptyParseError(parseError);
  if (probe.captureStatus?.load?.phase === "failed" || probe.captureStatus?.load?.phase === "canceled") {
    return `后端解析失败: ${probe.captureStatus.load.lastError || probe.captureStatus.load.phase}`;
  }
  if (probe.captureStatus && !activeCaptureConfirmed) return getPathMismatchError(opened, probe.captureStatus);
  if (probe.statusError) return `确认后端抓包状态失败: ${probe.statusError}`;
  if (probe.pageError) return `确认首屏数据页失败: ${probe.pageError}`;
  return "";
}

export function getActiveLoadFailureError(status: CaptureStatus | null, openedPath: string): string {
  if (!isActiveLoadForOpenedCapture(status, openedPath)) return "";
  const phase = status?.load?.phase;
  if (phase !== "failed" && phase !== "canceled") return "";
  return [
    phase === "canceled" ? "后端解析已取消" : "后端解析失败",
    `文件: ${status?.load?.filePath || openedPath}`,
    `profile: ${status?.load?.parserProfile || "unknown"}`,
    status?.load?.lastError ? `错误: ${status.load.lastError}` : "",
  ]
    .filter(Boolean)
    .join("；");
}

export function getCapturePreloadTimeoutErrorWithDiagnostics(probe: ProbeResult | null): string {
  if (!probe) return getCapturePreloadTimeoutError();
  if (probe.pageError) return `确认首屏数据页失败: ${probe.pageError}`;
  if (probe.statusError) return `确认后端抓包状态失败: ${probe.statusError}`;
  return getCapturePreloadTimeoutError();
}

function emptyStaleProbe(): ProbeResult {
  return {
    stale: true,
    page: null,
    pageError: "",
    captureStatus: null,
    statusError: "",
    activeCaptureConfirmed: false,
  };
}
