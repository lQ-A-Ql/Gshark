import type { Packet } from "../core/types";
import { packetPageHasPacket } from "./packetPagination";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

export interface PacketPageCommitSnapshot {
  readonly items: Packet[];
  readonly total: number;
  readonly hasMore: boolean;
}

interface PacketPageCommitOptions {
  readonly safeCursor: number;
  readonly page: PacketPageCommitSnapshot;
  readonly pageStartRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly setPageStart: Setter<number>;
  readonly setTotalPackets: Setter<number>;
  readonly setPackets: Setter<Packet[]>;
  readonly setSelectedPacketId: Setter<number | null>;
  readonly setSelectedPacketDetail: Setter<Packet | null>;
  readonly setSelectedPacketRawHex: Setter<string>;
  readonly setSelectedPacketLayers: Setter<Record<string, unknown> | null>;
  readonly setHasPrevPackets: Setter<boolean>;
  readonly setPacketPageError: Setter<string>;
  readonly setHasMorePackets: Setter<boolean>;
}

export function commitPacketPageState({
  safeCursor,
  page,
  pageStartRef,
  hasMorePacketsRef,
  setPageStart,
  setTotalPackets,
  setPackets,
  setSelectedPacketId,
  setSelectedPacketDetail,
  setSelectedPacketRawHex,
  setSelectedPacketLayers,
  setHasPrevPackets,
  setPacketPageError,
  setHasMorePackets,
}: PacketPageCommitOptions): void {
  pageStartRef.current = safeCursor;
  setPageStart(safeCursor);
  setTotalPackets(page.total);
  setPackets(page.items);
  setSelectedPacketId((prev) => {
    if (prev == null) return null;
    return packetPageHasPacket(page.items, prev) ? prev : null;
  });
  setSelectedPacketDetail((prev) => {
    if (!prev) return null;
    return packetPageHasPacket(page.items, prev.id) ? prev : null;
  });
  setSelectedPacketRawHex("");
  setSelectedPacketLayers(null);
  setHasPrevPackets(safeCursor > 0);
  setPacketPageError("");
  hasMorePacketsRef.current = page.hasMore;
  setHasMorePackets(page.hasMore);
}
