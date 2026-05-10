import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureTransactionStatus } from "./sentinelTypes";
import { buildOpenedCaptureFromPath, type OpenedCapture } from "./captureOpenState";
import { getCapturePreloadWorkingStatus } from "./capturePreloadStatus";
import { initializeCaptureStartState } from "./captureStartState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface ResolveOpenedCaptureOptions {
  readonly filePath?: string;
  readonly openPcapFile: () => Promise<OpenedCapture>;
}

export async function resolveOpenedCapture({
  filePath,
  openPcapFile,
}: ResolveOpenedCaptureOptions): Promise<OpenedCapture> {
  if (!filePath) {
    return openPcapFile();
  }
  return buildOpenedCaptureFromPath(filePath) ?? openPcapFile();
}

interface StartCaptureBackendOptions {
  readonly opened: OpenedCapture;
  readonly captureSeq: number;
  readonly captureSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly startStreamingPackets: (filePath: string, filter: string, signal?: AbortSignal) => Promise<unknown>;
}

export async function startCaptureBackend({
  opened,
  captureSeq,
  captureSeqRef,
  captureTaskScopeRef,
  startStreamingPackets,
}: StartCaptureBackendOptions): Promise<boolean> {
  const startTask = captureTaskScopeRef.current.beginTask("capture-start");
  try {
    await startStreamingPackets(opened.filePath, "", startTask.signal);
    return startTask.isCurrent() && captureSeq === captureSeqRef.current;
  } finally {
    startTask.finish();
  }
}

interface PrepareAndStartOpenedCaptureOptions extends StartCaptureBackendOptions {
  readonly openedAt: string;
  readonly hadActiveCapture: boolean;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadingRef: Ref<boolean>;
  readonly prepareForCaptureReplacement: () => Promise<void>;
  readonly setIsFilterLoading: Setter<boolean>;
  readonly setPacketPageError: Setter<string>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
  readonly setIsPreloadingCapture: Setter<boolean>;
  readonly setCaptureTransaction: Setter<CaptureTransactionStatus>;
  readonly setBackendStatus: (status: string) => void;
  readonly rememberRecentCapture: Parameters<typeof initializeCaptureStartState>[0]["rememberRecentCapture"];
}

export async function prepareAndStartOpenedCapture({
  opened,
  openedAt,
  hadActiveCapture,
  preloadProcessedRef,
  preloadTotalRef,
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  prepareForCaptureReplacement,
  setIsFilterLoading,
  setPacketPageError,
  setPreloadProcessed,
  setPreloadTotal,
  setIsPreloadingCapture,
  setCaptureTransaction,
  setBackendStatus,
  rememberRecentCapture,
  captureSeq,
  captureSeqRef,
  captureTaskScopeRef,
  startStreamingPackets,
}: PrepareAndStartOpenedCaptureOptions): Promise<boolean> {
  await prepareForCaptureReplacement();
  initializeCaptureStartState({
    opened,
    openedAt,
    hadActiveCapture,
    preloadProcessedRef,
    preloadTotalRef,
    parseFinishedRef,
    parseErrorRef,
    preloadingRef,
    setIsFilterLoading,
    setPacketPageError,
    setPreloadProcessed,
    setPreloadTotal,
    setIsPreloadingCapture,
    setCaptureTransaction,
    rememberRecentCapture,
  });

  const started = await startCaptureBackend({
    opened,
    captureSeq,
    captureSeqRef,
    captureTaskScopeRef,
    startStreamingPackets,
  });
  if (started) {
    setBackendStatus(getCapturePreloadWorkingStatus(opened.fileName));
  }
  return started;
}
