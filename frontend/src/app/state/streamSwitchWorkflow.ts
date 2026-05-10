import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { isAbortLikeError } from "../utils/asyncControl";
import type { CaptureTaskScope } from "../utils/captureTaskScope";
import { applyCachedStreamSwitch } from "./streamSwitchCache";
import { commitLoadedStreamSwitch } from "./streamSwitchCommit";
import {
  bumpStreamSwitchSequence,
  isLatestStreamSwitchSequence,
  type StreamSwitchSequences,
} from "./streamSwitchSequence";
import { resolveStreamSwitchTask } from "./streamSwitchTask";

export interface SetActiveStreamOptions {
  readonly backendConnected: boolean;
  readonly activeCapturePath: string;
  readonly protocol: StreamProtocol;
  readonly streamId: number;
  readonly streamSwitchSequences: StreamSwitchSequences;
  readonly captureTaskScope: CaptureTaskScope;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly applyHttpStream: (stream: HttpStream) => void;
  readonly applyTcpStream: (stream: BinaryStream) => void;
  readonly applyUdpStream: (stream: BinaryStream) => void;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawTcpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
  readonly fetchRawUdpStream: (streamId: number, signal: AbortSignal) => Promise<BinaryStream>;
  readonly recordMetric: (protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => void;
  readonly prefetchAdjacentStreams: (protocol: StreamProtocol, currentStreamId: number) => void;
  readonly setBackendStatus: (status: string) => void;
  readonly now?: () => number;
}

export async function setActiveStreamState(options: SetActiveStreamOptions): Promise<void> {
  if (!options.backendConnected || !options.activeCapturePath || options.streamId < 0) return;

  const now = options.now ?? (() => (typeof performance !== "undefined" ? performance.now() : Date.now()));
  const startedAt = now();
  const task = options.captureTaskScope.beginTask(`${options.protocol.toLowerCase()}-stream`);
  const requestSeq = bumpStreamSwitchSequence(options.streamSwitchSequences, options.protocol);
  const isLatest = () =>
    isLatestStreamSwitchSequence(options.streamSwitchSequences, options.protocol, requestSeq, task.isCurrent);
  const switchTask = resolveStreamSwitchTask(options);

  try {
    if (
      applyCachedStreamSwitch({
        cache: switchTask.cache,
        streamId: options.streamId,
        isLatest,
        apply: switchTask.applyStream,
      })
    ) {
      options.recordMetric(switchTask.protocol, now() - startedAt, true);
      options.prefetchAdjacentStreams(switchTask.protocol, options.streamId);
      return;
    }
    switchTask.applyStream(switchTask.loadingStream);
    const stream = await switchTask.fetchStream(options.streamId, task.signal);
    if (!isLatest()) return;
    commitLoadedStreamSwitch({
      protocol: switchTask.protocol,
      requestedStreamId: options.streamId,
      stream,
      cache: switchTask.cache,
      apply: switchTask.applyStream,
      startedAt,
      now,
      recordMetric: options.recordMetric,
      prefetchAdjacentStreams: options.prefetchAdjacentStreams,
    });
  } catch (error) {
    if (isLatest() && !isAbortLikeError(error, task.signal)) {
      options.setBackendStatus(error instanceof Error && error.message ? error.message : "流切换失败");
    }
  } finally {
    task.finish();
  }
}
