import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { applyStreamChunkPatches } from "./streamState";

type SupportedStream = HttpStream | BinaryStream;
type StreamPatch = { index: number; body: string };

interface CommitStreamPayloadPatchOptions<T extends SupportedStream> {
  readonly streamId: number;
  readonly patches: StreamPatch[];
  readonly setStream: (updater: (prev: T) => T) => void;
  readonly cache: Map<number, T>;
}

export function commitStreamPayloadPatches<T extends SupportedStream>({
  streamId,
  patches,
  setStream,
  cache,
}: CommitStreamPayloadPatchOptions<T>): void {
  setStream((prev) => (prev.id === streamId ? applyStreamChunkPatches(prev, patches) : prev));
  const cached = cache.get(streamId);
  if (!cached) {
    return;
  }
  cache.set(streamId, applyStreamChunkPatches(cached, patches));
}

interface CommitProtocolStreamPayloadPatchesOptions {
  readonly protocol: StreamProtocol;
  readonly streamId: number;
  readonly patches: StreamPatch[];
  readonly setHttpStream: (updater: (prev: HttpStream) => HttpStream) => void;
  readonly setTcpStream: (updater: (prev: BinaryStream) => BinaryStream) => void;
  readonly setUdpStream: (updater: (prev: BinaryStream) => BinaryStream) => void;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
}

export function commitProtocolStreamPayloadPatches({
  protocol,
  streamId,
  patches,
  setHttpStream,
  setTcpStream,
  setUdpStream,
  httpCache,
  tcpCache,
  udpCache,
}: CommitProtocolStreamPayloadPatchesOptions): void {
  if (protocol === "HTTP") {
    commitStreamPayloadPatches({
      streamId,
      patches,
      setStream: setHttpStream,
      cache: httpCache,
    });
    return;
  }

  if (protocol === "TCP") {
    commitStreamPayloadPatches({
      streamId,
      patches,
      setStream: setTcpStream,
      cache: tcpCache,
    });
    return;
  }

  commitStreamPayloadPatches({
    streamId,
    patches,
    setStream: setUdpStream,
    cache: udpCache,
  });
}
