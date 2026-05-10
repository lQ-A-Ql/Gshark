import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { PAGE_SIZE, PRELOAD_POLL_INTERVAL_MS, PRELOAD_SIGNAL_WAIT_MS } from "./captureConstants";
import { isCommittedCaptureStatusForPath } from "./captureCommitStatus";
import type { OpenedCapture } from "./captureOpenState";
import {
  CAPTURE_PRELOAD_TIMEOUT_MS,
  getCaptureEmptyParseError,
  getCapturePreloadTimeoutError,
} from "./capturePreloadStatus";

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

interface ProbeResult {
  readonly stale: boolean;
  readonly page: PacketsPageResult | null;
  readonly activeCaptureConfirmed: boolean;
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
  let firstPageLoaded = false;
  let activeCaptureConfirmed = false;
  let validatedFirstPage: CapturePreloadFirstPage | null = null;

  while (now() < waitDeadline && captureSeq === captureSeqRef.current) {
    const probe = await probeCapturePage({
      opened,
      filter,
      limit: firstPageLoaded ? 1 : pageSize,
      captureSeq,
      captureSeqRef,
      captureTaskScopeRef,
      listPacketsPage,
      getCaptureStatus,
    });
    if (probe.stale) return null;

    activeCaptureConfirmed = probe.activeCaptureConfirmed;
    const page = probe.page;
    if (page && activeCaptureConfirmed && page.total > 0) {
      setTotalPackets(page.total);
      if (preloadTotalRef.current <= 0) {
        setPreloadProcessed(page.total);
        preloadProcessedRef.current = page.total;
      }
    }
    if (!firstPageLoaded && page && activeCaptureConfirmed && page.total > 0) {
      validatedFirstPage = toFirstPage(page);
      firstPageLoaded = true;
    }

    if (activeCaptureConfirmed && firstPageLoaded) break;
    if (parseFinishedRef.current) break;

    await waitForCaptureSignal(firstPageLoaded ? signalWaitMs : pollIntervalMs);
  }

  if (captureSeq !== captureSeqRef.current) return null;

  const finalProbe = await probeCapturePage({
    opened,
    filter,
    limit: firstPageLoaded ? 1 : pageSize,
    captureSeq,
    captureSeqRef,
    captureTaskScopeRef,
    listPacketsPage,
    getCaptureStatus,
  });
  if (finalProbe.stale) return null;

  activeCaptureConfirmed = finalProbe.activeCaptureConfirmed;
  const finalPage = finalProbe.page;
  if (!firstPageLoaded && finalPage && activeCaptureConfirmed && finalPage.total > 0) {
    validatedFirstPage = toFirstPage(finalPage);
    firstPageLoaded = true;
  }
  if (finalPage?.total === 0 && parseFinishedRef.current) {
    throw new Error(getCaptureEmptyParseError(parseErrorRef.current));
  }
  if (!activeCaptureConfirmed || !firstPageLoaded || !validatedFirstPage) {
    throw new Error(getCapturePreloadTimeoutError());
  }

  return validatedFirstPage;
}

async function probeCapturePage({
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
  readonly listPacketsPage: CapturePreloadProbeOptions["listPacketsPage"];
  readonly getCaptureStatus: CapturePreloadProbeOptions["getCaptureStatus"];
}): Promise<ProbeResult> {
  const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
  try {
    const [page, captureStatus] = await Promise.all([
      listPacketsPage(0, limit, filter, probeTask.signal),
      getCaptureStatus(probeTask.signal).catch(() => null),
    ]);
    if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) {
      return { stale: true, page: null, activeCaptureConfirmed: false };
    }
    return {
      stale: false,
      page,
      activeCaptureConfirmed: isCommittedCaptureStatusForPath(captureStatus, opened.filePath),
    };
  } finally {
    probeTask.finish();
  }
}

function toFirstPage(page: PacketsPageResult): CapturePreloadFirstPage {
  return {
    items: page.items,
    total: page.total,
    hasMore: page.hasMore,
  };
}
