import type { BinaryStream, HttpStream } from "../core/types";
import { canSchedulePrefetch } from "./streamPrefetchPlan";

type SupportedStream = HttpStream | BinaryStream;

interface PrefetchTask {
  readonly signal: AbortSignal;
  isCurrent: () => boolean;
  finish: () => void;
}

interface ScheduleStreamPrefetchOptions<T extends SupportedStream> {
  readonly targetId: number;
  readonly taskKey: string;
  readonly cache: Map<number, T>;
  readonly inFlight: Set<number>;
  readonly beginTask: (key: string) => PrefetchTask;
  readonly fetchStream: (streamId: number, signal: AbortSignal) => Promise<T>;
  readonly maxInFlight?: number;
}

export function scheduleStreamPrefetch<T extends SupportedStream>({
  targetId,
  taskKey,
  cache,
  inFlight,
  beginTask,
  fetchStream,
  maxInFlight,
}: ScheduleStreamPrefetchOptions<T>): boolean {
  if (
    !canSchedulePrefetch({
      hasCached: cache.has(targetId),
      inFlight: inFlight.has(targetId),
      inFlightSize: inFlight.size,
      maxInFlight,
    })
  ) {
    return false;
  }

  const task = beginTask(taskKey);
  inFlight.add(targetId);
  void fetchStream(targetId, task.signal)
    .then((stream) => {
      if (task.isCurrent()) {
        cache.set(stream.id, stream);
      }
    })
    .catch(() => {
      // Prefetch is opportunistic; failures and aborts should not surface in UI.
    })
    .finally(() => {
      task.finish();
      inFlight.delete(targetId);
    });
  return true;
}
