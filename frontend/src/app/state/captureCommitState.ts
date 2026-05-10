import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import { buildCaptureFileMeta, type CaptureFileMeta, type OpenedCapture } from "./captureOpenState";
import { resetPacketViewportState } from "./captureResetState";
import { resetStreamRuntimeRefs, type StreamSwitchDurations, type StreamSwitchHits } from "./streamRuntimeReset";
import { type StreamSwitchSequences } from "./streamSwitchSequence";
import { EMPTY_SWITCH_METRICS } from "./streamState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface PacketPageSnapshot {
  readonly items: Packet[];
  readonly total: number;
  readonly hasMore: boolean;
}

interface CaptureCommitStateOptions {
  readonly opened: OpenedCapture;
  readonly validatedFirstPage: PacketPageSnapshot | null;
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
}

export function commitValidatedCaptureState({
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
}: CaptureCommitStateOptions): void {
  resetPacketViewportState({
    pageStartRef,
    hasMorePacketsRef,
    setPackets,
    setTotalPackets,
    setPageStart,
    setHasPrevPackets,
    setHasMorePackets,
    setSelectedPacketId,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
    hasMorePackets: true,
  });
  resetStreamRuntimeRefs({
    httpCache,
    tcpCache,
    udpCache,
    httpPrefetchInFlight,
    tcpPrefetchInFlight,
    udpPrefetchInFlight,
    switchSequences,
    switchDurationsRef,
    switchHitsRef,
  });
  setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
  resetAnalysisState();
  setFileMeta(buildCaptureFileMeta(opened));
  setCaptureRevision((prev) => prev + 1);
  activeCapturePathRef.current = opened.filePath;
  if (validatedFirstPage) {
    commitPacketPage(0, validatedFirstPage);
  }
}
