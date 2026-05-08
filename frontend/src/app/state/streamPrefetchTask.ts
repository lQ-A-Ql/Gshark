import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";

type SupportedStream = HttpStream | BinaryStream;

interface ResolveStreamPrefetchTaskOptions {
  readonly protocol: StreamProtocol;
  readonly targetId: number;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly httpInFlight: Set<number>;
  readonly tcpInFlight: Set<number>;
  readonly udpInFlight: Set<number>;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawTcpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
  readonly fetchRawUdpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
}

interface StreamPrefetchTask<T extends SupportedStream> {
  readonly taskKey: string;
  readonly cache: Map<number, T>;
  readonly inFlight: Set<number>;
  readonly fetchStream: (streamId: number, signal: AbortSignal) => Promise<T>;
}

export function resolveStreamPrefetchTask({
  protocol,
  targetId,
  httpCache,
  tcpCache,
  udpCache,
  httpInFlight,
  tcpInFlight,
  udpInFlight,
  fetchHttpStream,
  fetchRawTcpStream,
  fetchRawUdpStream,
}: ResolveStreamPrefetchTaskOptions): StreamPrefetchTask<SupportedStream> {
  if (protocol === "HTTP") {
    return {
      taskKey: `prefetch-http-${targetId}`,
      cache: httpCache,
      inFlight: httpInFlight,
      fetchStream: fetchHttpStream,
    };
  }

  if (protocol === "TCP") {
    return {
      taskKey: `prefetch-tcp-${targetId}`,
      cache: tcpCache,
      inFlight: tcpInFlight,
      fetchStream: fetchRawTcpStream,
    };
  }

  return {
    taskKey: `prefetch-udp-${targetId}`,
    cache: udpCache,
    inFlight: udpInFlight,
    fetchStream: fetchRawUdpStream,
  };
}
