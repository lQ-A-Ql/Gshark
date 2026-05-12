import { useCallback, type MutableRefObject } from "react";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../../core/types";
import { isAbortLikeError } from "../../utils/asyncControl";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { buildOpenedCaptureFromPath, type CaptureFileMeta, type OpenedCapture } from "../captureOpenState";
import { stopCapturePreloading } from "../captureParseRuntimeState";
import { getCaptureOpenDisconnectedStatus } from "../capturePreloadStatus";
import { resolveCapturePreloadFirstPage } from "../capturePreloadProbe";
import { prepareAndStartOpenedCapture, resolveOpenedCapture } from "../captureStartBackend";
import { buildFailedCaptureTransactionStatus } from "../captureTransactionStatus";
import { finalizeOpenedCapture } from "../captureFinalizeWorkflow";
import type { CaptureTransactionStatus } from "../sentinelTypes";
import type { StreamSwitchDurations, StreamSwitchHits } from "../streamRuntimeReset";
import type { StreamSwitchSequences } from "../streamSwitchSequence";
import type { CaptureStatus, PacketsPageResult } from "../../integrations/clients/captureClient";

type Ref<T> = MutableRefObject<T>;
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface UseCaptureStartWorkflowOptions {
  readonly backendConnected: boolean;
  readonly displayFilter: string;
  readonly activeCapturePathRef: Ref<string>;
  readonly captureSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly filterSeqRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly httpCacheRef: Ref<Map<number, HttpStream>>;
  readonly httpPrefetchInFlightRef: Ref<Set<number>>;
  readonly pageStartRef: Ref<number>;
  readonly parseErrorRef: Ref<string>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly preloadingRef: Ref<boolean>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly streamSwitchDurationsRef: Ref<StreamSwitchDurations>;
  readonly streamSwitchHitsRef: Ref<StreamSwitchHits>;
  readonly streamSwitchSequencesRef: Ref<StreamSwitchSequences>;
  readonly tcpCacheRef: Ref<Map<number, BinaryStream>>;
  readonly tcpPrefetchInFlightRef: Ref<Set<number>>;
  readonly udpCacheRef: Ref<Map<number, BinaryStream>>;
  readonly udpPrefetchInFlightRef: Ref<Set<number>>;
  readonly commitPacketPage: (safeCursor: number, page: Pick<PacketsPageResult, "items" | "total" | "hasMore">) => void;
  readonly getCaptureStatus: (signal?: AbortSignal) => Promise<CaptureStatus>;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter?: string,
    signal?: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly openPcapFile: () => Promise<OpenedCapture>;
  readonly prepareForCaptureReplacement: () => Promise<void>;
  readonly refreshAnalysisResult: (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>;
  readonly refreshStreamIndex: () => Promise<void>;
  readonly rememberRecentCapture: Parameters<typeof prepareAndStartOpenedCapture>[0]["rememberRecentCapture"];
  readonly resetAnalysisState: () => void;
  readonly setBackendStatus: (status: string) => void;
  readonly setCaptureRevision: Setter<number>;
  readonly setCaptureTransaction: Setter<CaptureTransactionStatus>;
  readonly setFileMeta: Setter<CaptureFileMeta>;
  readonly setHasMorePackets: Setter<boolean>;
  readonly setHasPrevPackets: Setter<boolean>;
  readonly setIsFilterLoading: Setter<boolean>;
  readonly setIsPreloadingCapture: Setter<boolean>;
  readonly setPacketPageError: Setter<string>;
  readonly setPackets: Setter<Packet[]>;
  readonly setPageStart: Setter<number>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
  readonly setSelectedPacketDetail: Setter<Packet | null>;
  readonly setSelectedPacketId: Setter<number | null>;
  readonly setSelectedPacketLayers: Setter<Record<string, unknown> | null>;
  readonly setSelectedPacketRawHex: Setter<string>;
  readonly setStreamSwitchMetrics: Setter<StreamSwitchMetrics>;
  readonly setTotalPackets: Setter<number>;
  readonly startStreamingPackets: (filePath: string, filter: string, signal?: AbortSignal) => Promise<unknown>;
  readonly waitForCaptureSignal: (delayMs: number) => Promise<void>;
  readonly wakeCaptureWaiters: () => void;
}

export function useCaptureStartWorkflow(options: UseCaptureStartWorkflowOptions) {
  return useCallback(
    async (filePath?: string, filterOverride?: string) => {
      if (!options.backendConnected) {
        options.setBackendStatus(getCaptureOpenDisconnectedStatus());
        return false;
      }

      const captureSeq = ++options.captureSeqRef.current;
      options.filterSeqRef.current += 1;
      const effectiveFilter = filterOverride ?? options.displayFilter;
      const hadActiveCapture = Boolean(options.activeCapturePathRef.current);
      let pendingCapture = buildOpenedCaptureFromPath(filePath ?? "");

      try {
        const opened = await resolveOpenedCapture({ filePath, openPcapFile: options.openPcapFile });
        pendingCapture = opened;

        const started = await prepareAndStartOpenedCapture({
          opened,
          openedAt: new Date().toISOString(),
          hadActiveCapture,
          preloadProcessedRef: options.preloadProcessedRef,
          preloadTotalRef: options.preloadTotalRef,
          parseFinishedRef: options.parseFinishedRef,
          parseErrorRef: options.parseErrorRef,
          preloadingRef: options.preloadingRef,
          setIsFilterLoading: options.setIsFilterLoading,
          setPacketPageError: options.setPacketPageError,
          setPreloadProcessed: options.setPreloadProcessed,
          setPreloadTotal: options.setPreloadTotal,
          setIsPreloadingCapture: options.setIsPreloadingCapture,
          setCaptureTransaction: options.setCaptureTransaction,
          setBackendStatus: options.setBackendStatus,
          rememberRecentCapture: options.rememberRecentCapture,
          captureSeq,
          captureSeqRef: options.captureSeqRef,
          captureTaskScopeRef: options.captureTaskScopeRef,
          prepareForCaptureReplacement: options.prepareForCaptureReplacement,
          startStreamingPackets: options.startStreamingPackets,
        });
        if (!started) return false;

        const validatedFirstPage = await resolveCapturePreloadFirstPage({
          opened,
          filter: effectiveFilter,
          captureSeq,
          captureSeqRef: options.captureSeqRef,
          captureTaskScopeRef: options.captureTaskScopeRef,
          parseFinishedRef: options.parseFinishedRef,
          parseErrorRef: options.parseErrorRef,
          preloadProcessedRef: options.preloadProcessedRef,
          preloadTotalRef: options.preloadTotalRef,
          listPacketsPage: options.listPacketsPage,
          getCaptureStatus: options.getCaptureStatus,
          waitForCaptureSignal: options.waitForCaptureSignal,
          setTotalPackets: options.setTotalPackets,
          setPreloadProcessed: options.setPreloadProcessed,
        });
        if (!validatedFirstPage) return false;

        return finalizeOpenedCapture({
          opened,
          validatedFirstPage,
          captureSeq,
          captureSeqRef: options.captureSeqRef,
          pageStartRef: options.pageStartRef,
          hasMorePacketsRef: options.hasMorePacketsRef,
          activeCapturePathRef: options.activeCapturePathRef,
          httpCache: options.httpCacheRef.current,
          tcpCache: options.tcpCacheRef.current,
          udpCache: options.udpCacheRef.current,
          httpPrefetchInFlight: options.httpPrefetchInFlightRef.current,
          tcpPrefetchInFlight: options.tcpPrefetchInFlightRef.current,
          udpPrefetchInFlight: options.udpPrefetchInFlightRef.current,
          switchSequences: options.streamSwitchSequencesRef.current,
          switchDurationsRef: options.streamSwitchDurationsRef,
          switchHitsRef: options.streamSwitchHitsRef,
          setPackets: options.setPackets,
          setTotalPackets: options.setTotalPackets,
          setPageStart: options.setPageStart,
          setHasPrevPackets: options.setHasPrevPackets,
          setHasMorePackets: options.setHasMorePackets,
          setSelectedPacketId: options.setSelectedPacketId,
          setSelectedPacketDetail: options.setSelectedPacketDetail,
          setSelectedPacketRawHex: options.setSelectedPacketRawHex,
          setSelectedPacketLayers: options.setSelectedPacketLayers,
          setStreamSwitchMetrics: options.setStreamSwitchMetrics,
          resetAnalysisState: options.resetAnalysisState,
          setFileMeta: options.setFileMeta,
          setCaptureRevision: options.setCaptureRevision,
          commitPacketPage: options.commitPacketPage,
          refreshStreamIndex: options.refreshStreamIndex,
          setCaptureTransaction: options.setCaptureTransaction,
          setBackendStatus: options.setBackendStatus,
          refreshAnalysisResult: options.refreshAnalysisResult,
        });
      } catch (error) {
        if (isAbortLikeError(error)) return false;
        if (captureSeq === options.captureSeqRef.current) {
          const failedTransaction = buildFailedCaptureTransactionStatus({
            error,
            parseError: options.parseErrorRef.current,
            hadActiveCapture,
            fallbackName: filePath?.trim() || "",
            fallbackPath: filePath?.trim() || "",
            pendingCaptureName: pendingCapture?.fileName,
            pendingCapturePath: pendingCapture?.filePath,
          });
          options.setCaptureTransaction(failedTransaction);
          options.setBackendStatus(failedTransaction.message);
        }
        return false;
      } finally {
        if (captureSeq === options.captureSeqRef.current) {
          stopCapturePreloading({
            preloadingRef: options.preloadingRef,
            setIsPreloadingCapture: options.setIsPreloadingCapture,
          });
          options.wakeCaptureWaiters();
        }
      }
    },
    [options],
  );
}
