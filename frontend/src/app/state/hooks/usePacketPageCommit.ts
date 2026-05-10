import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { Packet } from "../../core/types";
import { commitPacketPageState, type PacketPageCommitSnapshot } from "../packetPageCommit";

interface UsePacketPageCommitOptions {
  readonly hasMorePacketsRef: MutableRefObject<boolean>;
  readonly pageStartRef: MutableRefObject<number>;
  readonly setHasMorePackets: Dispatch<SetStateAction<boolean>>;
  readonly setHasPrevPackets: Dispatch<SetStateAction<boolean>>;
  readonly setPackets: Dispatch<SetStateAction<Packet[]>>;
  readonly setPacketPageError: Dispatch<SetStateAction<string>>;
  readonly setPageStart: Dispatch<SetStateAction<number>>;
  readonly setSelectedPacketDetail: Dispatch<SetStateAction<Packet | null>>;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setSelectedPacketLayers: Dispatch<SetStateAction<Record<string, unknown> | null>>;
  readonly setSelectedPacketRawHex: Dispatch<SetStateAction<string>>;
  readonly setTotalPackets: Dispatch<SetStateAction<number>>;
}

export function usePacketPageCommit(options: UsePacketPageCommitOptions) {
  return useCallback(
    (safeCursor: number, page: PacketPageCommitSnapshot) => {
      commitPacketPageState({
        safeCursor,
        page,
        pageStartRef: options.pageStartRef,
        hasMorePacketsRef: options.hasMorePacketsRef,
        setPageStart: options.setPageStart,
        setTotalPackets: options.setTotalPackets,
        setPackets: options.setPackets,
        setSelectedPacketId: options.setSelectedPacketId,
        setSelectedPacketDetail: options.setSelectedPacketDetail,
        setSelectedPacketRawHex: options.setSelectedPacketRawHex,
        setSelectedPacketLayers: options.setSelectedPacketLayers,
        setHasPrevPackets: options.setHasPrevPackets,
        setPacketPageError: options.setPacketPageError,
        setHasMorePackets: options.setHasMorePackets,
      });
    },
    [options],
  );
}
