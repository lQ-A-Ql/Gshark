import { createContext, useContext, type PropsWithChildren } from "react";
import type { BinaryStream, HttpStream, StreamSwitchMetrics } from "../../core/types";
import type { StreamIds } from "../streamState";
import type { PreparedPacketStream } from "../sentinelTypes";

export interface StreamContextValue {
  httpStream: HttpStream;
  tcpStream: BinaryStream;
  udpStream: BinaryStream;
  streamIds: StreamIds;
  setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  persistStreamPayloads: (
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
  ) => Promise<void>;
  streamSwitchMetrics: StreamSwitchMetrics;
  preparePacketStream: (
    packetId: number,
    preferredProtocol?: "HTTP" | "TCP" | "UDP",
    filterOverride?: string,
  ) => Promise<PreparedPacketStream>;
}

const StreamContext = createContext<StreamContextValue | null>(null);

export function StreamProvider({ children, value }: PropsWithChildren<{ value: StreamContextValue }>) {
  return <StreamContext.Provider value={value}>{children}</StreamContext.Provider>;
}

export function useStream() {
  const ctx = useContext(StreamContext);
  if (!ctx) {
    throw new Error("useStream must be used inside StreamProvider");
  }
  return ctx;
}
