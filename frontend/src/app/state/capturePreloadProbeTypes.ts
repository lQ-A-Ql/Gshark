import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { CapturePreloadDiagnostics } from "./capturePreloadDiagnostics";
import type { OpenedCapture } from "./captureOpenState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

export type CapturePreloadFirstPage = Pick<PacketsPageResult, "items" | "total" | "hasMore">;

export interface CapturePreloadProbeOptions {
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
