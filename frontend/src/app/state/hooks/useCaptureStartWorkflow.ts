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

export interface CaptureStartBackendContext {
  readonly backendConnected: boolean;
  readonly displayFilter: string;
}

export interface CaptureStartRefs {
  readonly activeCapturePathRef: Ref<string>;
  readonly captureSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly filterSeqRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly pageStartRef: Ref<number>;
  readonly parseErrorRef: Ref<string>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly preloadingRef: Ref<boolean>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
}

export interface CaptureStartStreamRefs {
  readonly httpCacheRef: Ref<Map<number, HttpStream>>;
  readonly tcpCacheRef: Ref<Map<number, BinaryStream>>;
  readonly udpCacheRef: Ref<Map<number, BinaryStream>>;
  readonly httpPrefetchInFlightRef: Ref<Set<number>>;
  readonly tcpPrefetchInFlightRef: Ref<Set<number>>;
  readonly udpPrefetchInFlightRef: Ref<Set<number>>;
  readonly streamSwitchDurationsRef: Ref<StreamSwitchDurations>;
  readonly streamSwitchHitsRef: Ref<StreamSwitchHits>;
  readonly streamSwitchSequencesRef: Ref<StreamSwitchSequences>;
}

export interface CaptureStartSetters {
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
}

export interface CaptureStartBackendClients {
  readonly getCaptureStatus: (signal?: AbortSignal) => Promise<CaptureStatus>;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter?: string,
    signal?: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly openPcapFile: () => Promise<OpenedCapture>;
  readonly startStreamingPackets: (filePath: string, filter: string, signal?: AbortSignal) => Promise<unknown>;
}

export interface CaptureStartHooks {
  readonly commitPacketPage: (safeCursor: number, page: Pick<PacketsPageResult, "items" | "total" | "hasMore">) => void;
  readonly prepareForCaptureReplacement: () => Promise<void>;
  readonly refreshAnalysisResult: (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>;
  readonly refreshStreamIndex: () => Promise<void>;
  readonly rememberRecentCapture: Parameters<typeof prepareAndStartOpenedCapture>[0]["rememberRecentCapture"];
  readonly resetAnalysisState: () => void;
  readonly waitForCaptureSignal: (delayMs: number) => Promise<void>;
  readonly wakeCaptureWaiters: () => void;
}

export interface UseCaptureStartWorkflowOptions {
  readonly context: CaptureStartBackendContext;
  readonly refs: CaptureStartRefs;
  readonly streamRefs: CaptureStartStreamRefs;
  readonly setters: CaptureStartSetters;
  readonly clients: CaptureStartBackendClients;
  readonly hooks: CaptureStartHooks;
}

export function useCaptureStartWorkflow(options: UseCaptureStartWorkflowOptions) {
  const { context, refs, streamRefs, setters, clients, hooks } = options;
  return useCallback(
    async (filePath?: string, filterOverride?: string) => {
      if (!context.backendConnected) {
        setters.setBackendStatus(getCaptureOpenDisconnectedStatus());
        return false;
      }

      const captureSeq = ++refs.captureSeqRef.current;
      refs.filterSeqRef.current += 1;
      const effectiveFilter = filterOverride ?? context.displayFilter;
      const hadActiveCapture = Boolean(refs.activeCapturePathRef.current);
      let pendingCapture = buildOpenedCaptureFromPath(filePath ?? "");

      try {
        const opened = await resolveOpenedCapture({ filePath, openPcapFile: clients.openPcapFile });
        pendingCapture = opened;

        const started = await prepareAndStartOpenedCapture({
          opened,
          openedAt: new Date().toISOString(),
          hadActiveCapture,
          preloadProcessedRef: refs.preloadProcessedRef,
          preloadTotalRef: refs.preloadTotalRef,
          parseFinishedRef: refs.parseFinishedRef,
          parseErrorRef: refs.parseErrorRef,
          preloadingRef: refs.preloadingRef,
          setIsFilterLoading: setters.setIsFilterLoading,
          setPacketPageError: setters.setPacketPageError,
          setPreloadProcessed: setters.setPreloadProcessed,
          setPreloadTotal: setters.setPreloadTotal,
          setIsPreloadingCapture: setters.setIsPreloadingCapture,
          setCaptureTransaction: setters.setCaptureTransaction,
          setBackendStatus: setters.setBackendStatus,
          rememberRecentCapture: hooks.rememberRecentCapture,
          captureSeq,
          captureSeqRef: refs.captureSeqRef,
          captureTaskScopeRef: refs.captureTaskScopeRef,
          prepareForCaptureReplacement: hooks.prepareForCaptureReplacement,
          startStreamingPackets: clients.startStreamingPackets,
        });
        if (!started) return false;

        const validatedFirstPage = await resolveCapturePreloadFirstPage({
          opened,
          filter: effectiveFilter,
          captureSeq,
          captureSeqRef: refs.captureSeqRef,
          captureTaskScopeRef: refs.captureTaskScopeRef,
          parseFinishedRef: refs.parseFinishedRef,
          parseErrorRef: refs.parseErrorRef,
          preloadProcessedRef: refs.preloadProcessedRef,
          preloadTotalRef: refs.preloadTotalRef,
          listPacketsPage: clients.listPacketsPage,
          getCaptureStatus: clients.getCaptureStatus,
          waitForCaptureSignal: hooks.waitForCaptureSignal,
          setTotalPackets: setters.setTotalPackets,
          setPreloadProcessed: setters.setPreloadProcessed,
        });
        if (!validatedFirstPage) return false;

        return finalizeOpenedCapture({
          opened,
          validatedFirstPage,
          captureSeq,
          captureSeqRef: refs.captureSeqRef,
          pageStartRef: refs.pageStartRef,
          hasMorePacketsRef: refs.hasMorePacketsRef,
          activeCapturePathRef: refs.activeCapturePathRef,
          httpCache: streamRefs.httpCacheRef.current,
          tcpCache: streamRefs.tcpCacheRef.current,
          udpCache: streamRefs.udpCacheRef.current,
          httpPrefetchInFlight: streamRefs.httpPrefetchInFlightRef.current,
          tcpPrefetchInFlight: streamRefs.tcpPrefetchInFlightRef.current,
          udpPrefetchInFlight: streamRefs.udpPrefetchInFlightRef.current,
          switchSequences: streamRefs.streamSwitchSequencesRef.current,
          switchDurationsRef: streamRefs.streamSwitchDurationsRef,
          switchHitsRef: streamRefs.streamSwitchHitsRef,
          setPackets: setters.setPackets,
          setTotalPackets: setters.setTotalPackets,
          setPageStart: setters.setPageStart,
          setHasPrevPackets: setters.setHasPrevPackets,
          setHasMorePackets: setters.setHasMorePackets,
          setSelectedPacketId: setters.setSelectedPacketId,
          setSelectedPacketDetail: setters.setSelectedPacketDetail,
          setSelectedPacketRawHex: setters.setSelectedPacketRawHex,
          setSelectedPacketLayers: setters.setSelectedPacketLayers,
          setStreamSwitchMetrics: setters.setStreamSwitchMetrics,
          resetAnalysisState: hooks.resetAnalysisState,
          setFileMeta: setters.setFileMeta,
          setCaptureRevision: setters.setCaptureRevision,
          commitPacketPage: hooks.commitPacketPage,
          refreshStreamIndex: hooks.refreshStreamIndex,
          setCaptureTransaction: setters.setCaptureTransaction,
          setBackendStatus: setters.setBackendStatus,
          refreshAnalysisResult: hooks.refreshAnalysisResult,
        });
      } catch (error) {
        if (isAbortLikeError(error)) return false;
        if (captureSeq === refs.captureSeqRef.current) {
          const failedTransaction = buildFailedCaptureTransactionStatus({
            error,
            parseError: refs.parseErrorRef.current,
            hadActiveCapture,
            fallbackName: filePath?.trim() || "",
            fallbackPath: filePath?.trim() || "",
            pendingCaptureName: pendingCapture?.fileName,
            pendingCapturePath: pendingCapture?.filePath,
          });
          setters.setCaptureTransaction(failedTransaction);
          setters.setBackendStatus(failedTransaction.message);
        }
        return false;
      } finally {
        if (captureSeq === refs.captureSeqRef.current) {
          stopCapturePreloading({
            preloadingRef: refs.preloadingRef,
            setIsPreloadingCapture: setters.setIsPreloadingCapture,
          });
          hooks.wakeCaptureWaiters();
        }
      }
    },
    [context, refs, streamRefs, setters, clients, hooks],
  );
}
