import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { buildLoadingBinaryStream, buildLoadingHttpStream } from "./streamState";

type SupportedStream = HttpStream | BinaryStream;

interface ResolveStreamSwitchTaskOptions {
  readonly protocol: StreamProtocol;
  readonly streamId: number;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly applyHttpStream: (stream: HttpStream) => void;
  readonly applyTcpStream: (stream: BinaryStream) => void;
  readonly applyUdpStream: (stream: BinaryStream) => void;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawTcpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
  readonly fetchRawUdpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
}

interface StreamSwitchTask {
  readonly protocol: StreamProtocol;
  readonly cache: Map<number, SupportedStream>;
  readonly applyStream: (stream: SupportedStream) => void;
  readonly loadingStream: SupportedStream;
  readonly fetchStream: (streamId: number, signal: AbortSignal) => Promise<SupportedStream>;
}

export function resolveStreamSwitchTask({
  protocol,
  streamId,
  httpCache,
  tcpCache,
  udpCache,
  applyHttpStream,
  applyTcpStream,
  applyUdpStream,
  fetchHttpStream,
  fetchRawTcpStream,
  fetchRawUdpStream,
}: ResolveStreamSwitchTaskOptions): StreamSwitchTask {
  if (protocol === "HTTP") {
    return {
      protocol,
      cache: httpCache as Map<number, SupportedStream>,
      applyStream: (stream) => applyHttpStream(stream as HttpStream),
      loadingStream: buildLoadingHttpStream(streamId),
      fetchStream: async (id, signal) => fetchHttpStream(id, signal),
    };
  }

  if (protocol === "TCP") {
    return {
      protocol,
      cache: tcpCache as Map<number, SupportedStream>,
      applyStream: (stream) => applyTcpStream(stream as BinaryStream),
      loadingStream: buildLoadingBinaryStream("TCP", streamId),
      fetchStream: async (id, signal) => fetchRawTcpStream(id, signal),
    };
  }

  return {
    protocol: "UDP",
    cache: udpCache as Map<number, SupportedStream>,
    applyStream: (stream) => applyUdpStream(stream as BinaryStream),
    loadingStream: buildLoadingBinaryStream("UDP", streamId),
    fetchStream: async (id, signal) => fetchRawUdpStream(id, signal),
  };
}
