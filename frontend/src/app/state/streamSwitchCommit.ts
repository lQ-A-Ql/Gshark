import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { isFastPathLoad } from "./streamState";

type SupportedStream = HttpStream | BinaryStream;

interface CommitLoadedStreamSwitchOptions<T extends SupportedStream> {
  readonly protocol: StreamProtocol;
  readonly requestedStreamId: number;
  readonly stream: T;
  readonly cache: Map<number, T>;
  readonly apply: (stream: T) => void;
  readonly startedAt: number;
  readonly now?: () => number;
  readonly recordMetric: (protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => void;
  readonly prefetchAdjacentStreams: (protocol: "HTTP" | "TCP" | "UDP", currentStreamId: number) => void;
}

function getNow(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

export function commitLoadedStreamSwitch<T extends SupportedStream>({
  protocol,
  requestedStreamId,
  stream,
  cache,
  apply,
  startedAt,
  now = getNow,
  recordMetric,
  prefetchAdjacentStreams,
}: CommitLoadedStreamSwitchOptions<T>): void {
  cache.set(stream.id, stream);
  apply(stream);
  const elapsed = now() - startedAt;
  recordMetric(protocol, elapsed, isFastPathLoad(stream.loadMeta));
  prefetchAdjacentStreams(protocol, requestedStreamId);
}
