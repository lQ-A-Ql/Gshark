import type { BinaryStream, HttpStream } from "../core/types";
import { markCachedLoad } from "./streamState";

type SupportedStream = HttpStream | BinaryStream;

interface ApplyCachedStreamSwitchOptions<T extends SupportedStream> {
  readonly cache: Map<number, T>;
  readonly streamId: number;
  readonly isLatest: () => boolean;
  readonly apply: (stream: T) => void;
}

export function applyCachedStreamSwitch<T extends SupportedStream>({
  cache,
  streamId,
  isLatest,
  apply,
}: ApplyCachedStreamSwitchOptions<T>): boolean {
  const cached = cache.get(streamId);
  if (!cached || !isLatest()) {
    return false;
  }
  apply(markCachedLoad(cached));
  return true;
}
