import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import type { StreamIds } from "./streamState";
import { getStreamIdsForProtocol } from "./streamState";
import { pickAdjacentStreamTargets } from "./streamPrefetchPlan";
import { resolveStreamPrefetchTask } from "./streamPrefetchTask";
import { scheduleStreamPrefetch } from "./streamPrefetchScheduler";

interface PrefetchTask {
  readonly signal: AbortSignal;
  isCurrent: () => boolean;
  finish: () => void;
}

export interface PrefetchAdjacentStreamsOptions {
  readonly backendConnected: boolean;
  readonly activeCapturePath: string;
  readonly protocol: StreamProtocol;
  readonly currentStreamId: number;
  readonly limit: number;
  readonly streamIds: StreamIds;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly httpInFlight: Set<number>;
  readonly tcpInFlight: Set<number>;
  readonly udpInFlight: Set<number>;
  readonly beginTask: (key: string) => PrefetchTask;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawTcpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
  readonly fetchRawUdpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
}

export function prefetchAdjacentStreamsState(options: PrefetchAdjacentStreamsOptions): number {
  const { backendConnected, activeCapturePath, currentStreamId, limit, protocol } = options;
  if (!backendConnected || !activeCapturePath || currentStreamId < 0 || limit <= 0) {
    return 0;
  }

  let scheduled = 0;
  const ids = getStreamIdsForProtocol(options.streamIds, protocol);
  for (const targetId of pickAdjacentStreamTargets(ids, currentStreamId, limit)) {
    const { taskKey, cache, inFlight, fetchStream } = resolveStreamPrefetchTask({
      protocol,
      targetId,
      httpCache: options.httpCache,
      tcpCache: options.tcpCache,
      udpCache: options.udpCache,
      httpInFlight: options.httpInFlight,
      tcpInFlight: options.tcpInFlight,
      udpInFlight: options.udpInFlight,
      fetchHttpStream: options.fetchHttpStream,
      fetchRawTcpStream: options.fetchRawTcpStream,
      fetchRawUdpStream: options.fetchRawUdpStream,
    });
    if (scheduleStreamPrefetch({ targetId, taskKey, cache, inFlight, beginTask: options.beginTask, fetchStream })) {
      scheduled += 1;
    }
  }
  return scheduled;
}
