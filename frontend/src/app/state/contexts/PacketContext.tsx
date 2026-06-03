import { createContext, useContext, type PropsWithChildren } from "react";
import type { buildProtocolTree } from "../../core/engine";
import type { Packet } from "../../core/types";

export interface PacketContextValue {
  packets: Packet[];
  totalPackets: number;
  currentPage: number;
  totalPages: number;
  filteredPackets: Packet[];
  hasMorePackets: boolean;
  hasPrevPackets: boolean;
  isPageLoading: boolean;
  isFilterLoading: boolean;
  packetPageError: string;
  loadMorePackets: () => Promise<void>;
  loadPrevPackets: () => Promise<void>;
  jumpToPage: (page: number) => Promise<void>;
  retryPacketPage: () => Promise<void>;
  locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  selectedPacket: Packet | null;
  selectedPacketRawHex: string;
  selectedPacketId: number | null;
  selectPacket: (id: number) => void;
  protocolTree: ReturnType<typeof buildProtocolTree>;
  hexDump: string;
}

const PacketContext = createContext<PacketContextValue | null>(null);

export function PacketProvider({ children, value }: PropsWithChildren<{ value: PacketContextValue }>) {
  return <PacketContext.Provider value={value}>{children}</PacketContext.Provider>;
}

export function usePacket() {
  const ctx = useContext(PacketContext);
  if (!ctx) {
    throw new Error("usePacket must be used inside PacketProvider");
  }
  return ctx;
}
