import { buildHexDump, buildProtocolTree, buildProtocolTreeFromLayers } from "../core/engine";
import type { Packet } from "../core/types";
import { getCurrentPacketPage, getTotalPacketPages } from "./packetPagination";
import { resolveSelectedPacket } from "./selectedPacketState";

interface SentinelDerivedViewOptions {
  readonly packets: Packet[];
  readonly selectedPacketId: number | null;
  readonly selectedPacketDetail: Packet | null;
  readonly selectedPacketLayers: Record<string, unknown> | null;
  readonly pageStart: number;
  readonly totalPackets: number;
  readonly pageSize: number;
}

export function buildSentinelDerivedView({
  packets,
  selectedPacketId,
  selectedPacketDetail,
  selectedPacketLayers,
  pageStart,
  totalPackets,
  pageSize,
}: SentinelDerivedViewOptions) {
  const selectedPacket = resolveSelectedPacket(packets, selectedPacketId, selectedPacketDetail);
  const protocolTree = selectedPacketLayers
    ? buildProtocolTreeFromLayers(selectedPacketLayers, selectedPacket)
    : buildProtocolTree(selectedPacket);

  return {
    filteredPackets: packets,
    selectedPacket,
    protocolTree,
    hexDump: buildHexDump(selectedPacket),
    currentPage: getCurrentPacketPage(pageStart, pageSize),
    totalPages: getTotalPacketPages(totalPackets, pageSize),
  };
}
