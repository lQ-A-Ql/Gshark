import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { Packet } from "../../core/types";
import { resetPacketViewportState } from "../captureResetState";

interface UsePacketViewportResetOptions {
  readonly cancelPacketPageLoad: () => void;
  readonly hasMorePacketsRef: MutableRefObject<boolean>;
  readonly pageStartRef: MutableRefObject<number>;
  readonly setHasMorePackets: Dispatch<SetStateAction<boolean>>;
  readonly setHasPrevPackets: Dispatch<SetStateAction<boolean>>;
  readonly setPackets: Dispatch<SetStateAction<Packet[]>>;
  readonly setPageStart: Dispatch<SetStateAction<number>>;
  readonly setSelectedPacketDetail: Dispatch<SetStateAction<Packet | null>>;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setSelectedPacketLayers: Dispatch<SetStateAction<Record<string, unknown> | null>>;
  readonly setSelectedPacketRawHex: Dispatch<SetStateAction<string>>;
  readonly setTotalPackets: Dispatch<SetStateAction<number>>;
}

export function usePacketViewportReset(options: UsePacketViewportResetOptions) {
  return useCallback(() => {
    options.cancelPacketPageLoad();
    resetPacketViewportState({
      pageStartRef: options.pageStartRef,
      hasMorePacketsRef: options.hasMorePacketsRef,
      setPackets: options.setPackets,
      setTotalPackets: options.setTotalPackets,
      setPageStart: options.setPageStart,
      setHasPrevPackets: options.setHasPrevPackets,
      setHasMorePackets: options.setHasMorePackets,
      setSelectedPacketId: options.setSelectedPacketId,
      setSelectedPacketDetail: options.setSelectedPacketDetail,
      setSelectedPacketRawHex: options.setSelectedPacketRawHex,
      setSelectedPacketLayers: options.setSelectedPacketLayers,
    });
  }, [options]);
}
