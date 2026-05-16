import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { PAGE_SIZE, PRELOAD_POLL_INTERVAL_MS, PRELOAD_SIGNAL_WAIT_MS } from "./captureConstants";
import type { CapturePreloadDiagnostics } from "./capturePreloadDiagnostics";
import {
  applyProbePageState,
  canUseDegradedFirstPage,
  getCapturePreloadTimeoutErrorWithDiagnostics,
  getParseFinishedProbeError,
  getProbePhase,
  probeCapturePage,
  publishDiagnostics,
  publishReadyDiagnostics,
  type ProbeResult,
} from "./capturePreloadProbeStep";
import type { OpenedCapture } from "./captureOpenState";
import { CAPTURE_PRELOAD_TIMEOUT_MS } from "./capturePreloadStatus";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

export type CapturePreloadFirstPage = Pick<PacketsPageResult, "items" | "total" | "hasMore">;

interface CapturePreloadProbeOptions {
  readonly opened: OpenedCapture;
  readonly filter: string;
  readonly captureSeq: number;
  readonly captureSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly hadActiveCapture?: boolean;
  readonly onDiagnostics?: (diagnostics: CapturePreloadDiagnostics) => void;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter?: string,
    signal?: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly getCaptureStatus: (signal?: AbortSignal) => Promise<CaptureStatus>;
  readonly waitForCaptureSignal: (delayMs: number) => Promise<void>;
  readonly setTotalPackets: Setter<number>;
  readonly setPreloadProcessed: Setter<number>;
  readonly pageSize?: number;
  readonly timeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly signalWaitMs?: number;
  readonly now?: () => number;
}

export async function resolveCapturePreloadFirstPage({
  opened,
  filter,
  captureSeq,
  captureSeqRef,
  captureTaskScopeRef,
  parseFinishedRef,
  parseErrorRef,
  preloadProcessedRef,
  preloadTotalRef,
  hadActiveCapture = false,
  onDiagnostics,
  listPacketsPage,
  getCaptureStatus,
  waitForCaptureSignal,
  setTotalPackets,
  setPreloadProcessed,
  pageSize = PAGE_SIZE,
  timeoutMs = CAPTURE_PRELOAD_TIMEOUT_MS,
  pollIntervalMs = PRELOAD_POLL_INTERVAL_MS,
  signalWaitMs = PRELOAD_SIGNAL_WAIT_MS,
  now = Date.now,
}: CapturePreloadProbeOptions): Promise<CapturePreloadFirstPage | null> {
  const waitDeadline = now() + timeoutMs;
  let activeCaptureConfirmed = false;
  let pageState = {
    firstPageLoaded: false,
    candidateFirstPage: null as CapturePreloadFirstPage | null,
    validatedFirstPage: null as CapturePreloadFirstPage | null,
  };
  let lastProbe: ProbeResult | null = null;

  while (now() < waitDeadline && captureSeq === captureSeqRef.current) {
    const probe = await probeCapturePage({
      opened,
      filter,
      limit: pageState.firstPageLoaded ? 1 : pageSize,
      captureSeq,
      captureSeqRef,
      captureTaskScopeRef,
      listPacketsPage,
      getCaptureStatus,
    });
    if (probe.stale) return null;
    lastProbe = probe;

    activeCaptureConfirmed = probe.activeCaptureConfirmed;
    pageState = applyProbePageState({
      page: probe.page,
      activeCaptureConfirmed,
      state: pageState,
      preloadProcessedRef,
      preloadTotalRef,
      setTotalPackets,
      setPreloadProcessed,
    });
    publishDiagnostics({
      opened,
      probe,
      phase: getProbePhase(probe, activeCaptureConfirmed, Boolean(pageState.candidateFirstPage)),
      onDiagnostics,
    });

    if (activeCaptureConfirmed && pageState.firstPageLoaded) break;
    if (parseFinishedRef.current) break;

    await waitForCaptureSignal(pageState.firstPageLoaded ? signalWaitMs : pollIntervalMs);
  }

  if (captureSeq !== captureSeqRef.current) return null;

  const finalProbe = await probeCapturePage({
    opened,
    filter,
    limit: pageState.firstPageLoaded ? 1 : pageSize,
    captureSeq,
    captureSeqRef,
    captureTaskScopeRef,
    listPacketsPage,
    getCaptureStatus,
  });
  if (finalProbe.stale) return null;
  lastProbe = finalProbe;

  activeCaptureConfirmed = finalProbe.activeCaptureConfirmed;
  pageState = applyProbePageState({
    page: finalProbe.page,
    activeCaptureConfirmed,
    state: pageState,
    preloadProcessedRef,
    preloadTotalRef,
    setTotalPackets,
    setPreloadProcessed,
  });
  publishDiagnostics({
    opened,
    probe: finalProbe,
    phase: getProbePhase(finalProbe, activeCaptureConfirmed, Boolean(pageState.candidateFirstPage)),
    onDiagnostics,
  });

  if (
    canUseDegradedFirstPage({
      hadActiveCapture,
      parseFinished: parseFinishedRef.current,
      parseError: parseErrorRef.current,
      candidateFirstPage: pageState.candidateFirstPage,
      probe: finalProbe,
    })
  ) {
    publishReadyDiagnostics(opened, finalProbe, onDiagnostics, true);
    return pageState.candidateFirstPage!;
  }
  if (parseFinishedRef.current) {
    const finishedError = getParseFinishedProbeError({
      opened,
      probe: finalProbe,
      activeCaptureConfirmed,
      parseError: parseErrorRef.current,
    });
    if (finishedError) throw new Error(finishedError);
  }
  if (!activeCaptureConfirmed || !pageState.firstPageLoaded || !pageState.validatedFirstPage) {
    throw new Error(getCapturePreloadTimeoutErrorWithDiagnostics(lastProbe));
  }

  publishReadyDiagnostics(opened, finalProbe, onDiagnostics);
  return pageState.validatedFirstPage;
}
