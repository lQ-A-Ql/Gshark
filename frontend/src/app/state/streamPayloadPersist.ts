import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { commitProtocolStreamPayloadPatches } from "./streamPayloadPatch";

type StreamPatch = { index: number; body: string };

interface PersistStreamPayloadsOptions {
  readonly protocol: StreamProtocol;
  readonly streamId: number;
  readonly patches: StreamPatch[];
  readonly backendConnected: boolean;
  readonly updateStreamPayloads: (
    protocol: StreamProtocol,
    streamId: number,
    patches: StreamPatch[],
  ) => Promise<unknown>;
  readonly startTransition: (callback: () => void) => void;
  readonly setHttpStream: (updater: (prev: HttpStream) => HttpStream) => void;
  readonly setTcpStream: (updater: (prev: BinaryStream) => BinaryStream) => void;
  readonly setUdpStream: (updater: (prev: BinaryStream) => BinaryStream) => void;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
}

export async function persistStreamPayloadsState({
  protocol,
  streamId,
  patches,
  backendConnected,
  updateStreamPayloads,
  startTransition,
  setHttpStream,
  setTcpStream,
  setUdpStream,
  httpCache,
  tcpCache,
  udpCache,
}: PersistStreamPayloadsOptions): Promise<void> {
  if (!backendConnected || streamId < 0 || patches.length === 0) return;
  await updateStreamPayloads(protocol, streamId, patches);

  startTransition(() => {
    commitProtocolStreamPayloadPatches({
      protocol,
      streamId,
      patches,
      setHttpStream,
      setTcpStream,
      setUdpStream,
      httpCache,
      tcpCache,
      udpCache,
    });
  });
}
