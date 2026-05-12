import { useRef, useState, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { Packet } from "../../core/types";
import type { PacketLocateResult, PacketsPageResult } from "../../integrations/clients/captureClient";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { PAGE_SIZE } from "../captureConstants";
import { usePacketLocateById } from "./usePacketLocateById";
import { usePacketPageCancellation } from "./usePacketPageCancellation";
import { usePacketPageCommit } from "./usePacketPageCommit";
import { usePacketPageLoad } from "./usePacketPageLoad";
import { usePacketPageNavigation } from "./usePacketPageNavigation";
import { usePacketViewportReset } from "./usePacketViewportReset";
import { useSelectedPacketState } from "./useSelectedPacketState";
import { useScheduledPacketPageLoad } from "./useScheduledPacketPageLoad";

interface UsePacketPageStateOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly displayFilter: string;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter?: string,
    signal?: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly locatePacketPage: (
    packetId: number,
    limit: number,
    filter: string,
    signal: AbortSignal,
  ) => Promise<PacketLocateResult>;
  readonly loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  readonly loadRawHex: (packetId: number, signal: AbortSignal) => Promise<string>;
  readonly loadLayers: (packetId: number, signal: AbortSignal) => Promise<Record<string, unknown> | null>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setDisplayFilter: Dispatch<SetStateAction<string>>;
}

export function usePacketPageState({
  activeCapturePathRef,
  backendConnected,
  captureTaskScopeRef,
  displayFilter,
  listPacketsPage,
  locatePacketPage,
  loadPacket,
  loadRawHex,
  loadLayers,
  setBackendStatus,
  setDisplayFilter,
}: UsePacketPageStateOptions) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [pageStart, setPageStart] = useState(0);
  const [hasMorePackets, setHasMorePackets] = useState(false);
  const [hasPrevPackets, setHasPrevPackets] = useState(false);
  const [isPageLoading, setIsPageLoading] = useState(false);
  const [isFilterLoading, setIsFilterLoading] = useState(false);
  const [packetPageError, setPacketPageError] = useState("");

  const pageStartRef = useRef(0);
  const packetPageSeqRef = useRef(0);
  const hasMorePacketsRef = useRef(false);
  const loadMoreScheduledRef = useRef<number | null>(null);

  const selectedPacketState = useSelectedPacketState({
    packets,
    pageStart,
    totalPackets,
    pageSize: PAGE_SIZE,
    captureTaskScopeRef,
    loadPacket,
    loadRawHex,
    loadLayers,
  });

  const cancelPacketPageLoad = usePacketPageCancellation({
    captureTaskScopeRef,
    packetPageSeqRef,
    setIsPageLoading,
  });

  const commitPacketPage = usePacketPageCommit({
    hasMorePacketsRef,
    pageStartRef,
    setHasMorePackets,
    setHasPrevPackets,
    setPackets,
    setPacketPageError,
    setPageStart,
    setSelectedPacketDetail: selectedPacketState.setSelectedPacketDetail,
    setSelectedPacketId: selectedPacketState.setSelectedPacketId,
    setSelectedPacketLayers: selectedPacketState.setSelectedPacketLayers,
    setSelectedPacketRawHex: selectedPacketState.setSelectedPacketRawHex,
    setTotalPackets,
  });

  const resetPacketViewport = usePacketViewportReset({
    cancelPacketPageLoad,
    hasMorePacketsRef,
    pageStartRef,
    setHasMorePackets,
    setHasPrevPackets,
    setPackets,
    setPageStart,
    setSelectedPacketDetail: selectedPacketState.setSelectedPacketDetail,
    setSelectedPacketId: selectedPacketState.setSelectedPacketId,
    setSelectedPacketLayers: selectedPacketState.setSelectedPacketLayers,
    setSelectedPacketRawHex: selectedPacketState.setSelectedPacketRawHex,
    setTotalPackets,
  });

  const loadPacketPage = usePacketPageLoad({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    commitPacketPage,
    displayFilter,
    listPacketsPage,
    packetPageSeqRef,
    pageSize: PAGE_SIZE,
    setBackendStatus,
    setIsFilterLoading,
    setIsPageLoading,
    setPacketPageError,
  });

  const { jumpToPage, loadMorePackets, loadPrevPackets, retryPacketPage } = usePacketPageNavigation({
    displayFilter,
    loadPacketPage,
    pageSize: PAGE_SIZE,
    pageStartRef,
    setBackendStatus,
    totalPackets,
  });

  const locatePacketById = usePacketLocateById({
    activeCapturePathRef,
    captureTaskScopeRef,
    displayFilter,
    loadPacketPage,
    locatePacketPage,
    pageSize: PAGE_SIZE,
    setBackendStatus,
    setDisplayFilter,
    setSelectedPacketId: selectedPacketState.setSelectedPacketId,
  });

  const scheduleLoadMore = useScheduledPacketPageLoad({ loadMoreScheduledRef, pageStartRef, loadPacketPage });

  return {
    packets,
    setPackets,
    totalPackets,
    setTotalPackets,
    pageStart,
    setPageStart,
    hasMorePackets,
    setHasMorePackets,
    hasPrevPackets,
    setHasPrevPackets,
    isPageLoading,
    setIsPageLoading,
    isFilterLoading,
    setIsFilterLoading,
    packetPageError,
    setPacketPageError,
    pageStartRef,
    packetPageSeqRef,
    hasMorePacketsRef,
    loadMoreScheduledRef,
    cancelPacketPageLoad,
    commitPacketPage,
    resetPacketViewport,
    loadPacketPage,
    loadMorePackets,
    loadPrevPackets,
    jumpToPage,
    retryPacketPage,
    locatePacketById,
    scheduleLoadMore,
    ...selectedPacketState,
  };
}
