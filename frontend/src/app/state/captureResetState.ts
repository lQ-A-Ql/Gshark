import type { Packet } from "../core/types";

type Setter<T> = (value: T | ((prev: T) => T)) => void;
type Ref<T> = { current: T };

interface PacketViewportResetOptions {
  readonly pageStartRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly setPackets: Setter<Packet[]>;
  readonly setTotalPackets: Setter<number>;
  readonly setPageStart: Setter<number>;
  readonly setHasPrevPackets: Setter<boolean>;
  readonly setHasMorePackets: Setter<boolean>;
  readonly setSelectedPacketId: Setter<number | null>;
  readonly setSelectedPacketDetail: Setter<Packet | null>;
  readonly setSelectedPacketRawHex: Setter<string>;
  readonly setSelectedPacketLayers: Setter<Record<string, unknown> | null>;
  readonly hasMorePackets?: boolean;
}

interface PreloadCounterResetOptions {
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
}

export function resetPacketViewportState({
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
  hasMorePackets = false,
}: PacketViewportResetOptions): void {
  pageStartRef.current = 0;
  setPageStart(0);
  setPackets([]);
  setTotalPackets(0);
  setHasPrevPackets(false);
  hasMorePacketsRef.current = hasMorePackets;
  setHasMorePackets(hasMorePackets);
  setSelectedPacketId(null);
  setSelectedPacketDetail(null);
  setSelectedPacketRawHex("");
  setSelectedPacketLayers(null);
}

export function resetPreloadCounterState({
  preloadProcessedRef,
  preloadTotalRef,
  setPreloadProcessed,
  setPreloadTotal,
}: PreloadCounterResetOptions): void {
  setPreloadProcessed(0);
  setPreloadTotal(0);
  preloadProcessedRef.current = 0;
  preloadTotalRef.current = 0;
}
