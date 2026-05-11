import { useMemo } from "react";
import type { Packet } from "../../core/types";
import { buildSentinelDerivedView } from "../sentinelDerivedView";

type UseSentinelDerivedViewOptions = {
  readonly packets: Packet[];
  readonly selectedPacketId: number | null;
  readonly selectedPacketDetail: Packet | null;
  readonly selectedPacketLayers: Record<string, unknown> | null;
  readonly pageStart: number;
  readonly totalPackets: number;
  readonly pageSize: number;
};

export function useSentinelDerivedView({
  packets,
  selectedPacketId,
  selectedPacketDetail,
  selectedPacketLayers,
  pageStart,
  totalPackets,
  pageSize,
}: UseSentinelDerivedViewOptions) {
  return useMemo(
    () =>
      buildSentinelDerivedView({
        packets,
        selectedPacketId,
        selectedPacketDetail,
        selectedPacketLayers,
        pageStart,
        totalPackets,
        pageSize,
      }),
    [packets, pageSize, pageStart, selectedPacketDetail, selectedPacketId, selectedPacketLayers, totalPackets],
  );
}
