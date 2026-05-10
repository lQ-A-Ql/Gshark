import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import type { CaptureFileMeta, OpenedCapture } from "./captureOpenState";
import { commitValidatedCaptureState } from "./captureCommitState";
import { getCapturePreloadDoneStatus } from "./capturePreloadStatus";
import { createIdleCaptureTransactionStatus } from "./captureTransactionStatus";
import type { StreamSwitchDurations, StreamSwitchHits } from "./streamRuntimeReset";
import type { StreamSwitchSequences } from "./streamSwitchSequence";
import type { CaptureTransactionStatus } from "./sentinelTypes";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface PacketPageSnapshot {
  readonly items: Packet[];
  readonly total: number;
  readonly hasMore: boolean;
}

interface FinalizeOpenedCaptureOptions {
  readonly opened: OpenedCapture;
  readonly validatedFirstPage: PacketPageSnapshot;
  readonly captureSeq: number;
  readonly captureSeqRef: Ref<number>;
  readonly pageStartRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly activeCapturePathRef: Ref<string>;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly httpPrefetchInFlight: Set<number>;
  readonly tcpPrefetchInFlight: Set<number>;
  readonly udpPrefetchInFlight: Set<number>;
  readonly switchSequences: StreamSwitchSequences;
  readonly switchDurationsRef: Ref<StreamSwitchDurations>;
  readonly switchHitsRef: Ref<StreamSwitchHits>;
  readonly setPackets: Setter<Packet[]>;
  readonly setTotalPackets: Setter<number>;
  readonly setPageStart: Setter<number>;
  readonly setHasPrevPackets: Setter<boolean>;
  readonly setHasMorePackets: Setter<boolean>;
  readonly setSelectedPacketId: Setter<number | null>;
  readonly setSelectedPacketDetail: Setter<Packet | null>;
  readonly setSelectedPacketRawHex: Setter<string>;
  readonly setSelectedPacketLayers: Setter<Record<string, unknown> | null>;
  readonly setStreamSwitchMetrics: Setter<StreamSwitchMetrics>;
  readonly resetAnalysisState: () => void;
  readonly setFileMeta: Setter<CaptureFileMeta>;
  readonly setCaptureRevision: Setter<number>;
  readonly commitPacketPage: (safeCursor: number, page: PacketPageSnapshot) => void;
  readonly refreshStreamIndex: () => Promise<void>;
  readonly setCaptureTransaction: Setter<CaptureTransactionStatus>;
  readonly setBackendStatus: (status: string) => void;
  readonly refreshAnalysisResult: (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>;
}

export async function finalizeOpenedCapture({
  opened,
  validatedFirstPage,
  captureSeq,
  captureSeqRef,
  pageStartRef,
  hasMorePacketsRef,
  activeCapturePathRef,
  httpCache,
  tcpCache,
  udpCache,
  httpPrefetchInFlight,
  tcpPrefetchInFlight,
  udpPrefetchInFlight,
  switchSequences,
  switchDurationsRef,
  switchHitsRef,
  setPackets,
  setTotalPackets,
  setPageStart,
  setHasPrevPackets,
  setHasMorePackets,
  setSelectedPacketId,
  setSelectedPacketDetail,
  setSelectedPacketRawHex,
  setSelectedPacketLayers,
  setStreamSwitchMetrics,
  resetAnalysisState,
  setFileMeta,
  setCaptureRevision,
  commitPacketPage,
  refreshStreamIndex,
  setCaptureTransaction,
  setBackendStatus,
  refreshAnalysisResult,
}: FinalizeOpenedCaptureOptions): Promise<boolean> {
  commitValidatedCaptureState({
    opened,
    validatedFirstPage,
    pageStartRef,
    hasMorePacketsRef,
    activeCapturePathRef,
    httpCache,
    tcpCache,
    udpCache,
    httpPrefetchInFlight,
    tcpPrefetchInFlight,
    udpPrefetchInFlight,
    switchSequences,
    switchDurationsRef,
    switchHitsRef,
    setPackets,
    setTotalPackets,
    setPageStart,
    setHasPrevPackets,
    setHasMorePackets,
    setSelectedPacketId,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
    setStreamSwitchMetrics,
    resetAnalysisState,
    setFileMeta,
    setCaptureRevision,
    commitPacketPage,
  });

  await refreshStreamIndex();
  if (captureSeq !== captureSeqRef.current) return false;

  setCaptureTransaction(createIdleCaptureTransactionStatus(true));
  setBackendStatus(getCapturePreloadDoneStatus(opened.fileName));
  void refreshAnalysisResult({ capturePath: opened.filePath, quietSuccess: true });
  return true;
}
