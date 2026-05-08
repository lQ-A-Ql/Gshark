import type { BinaryStream, HttpStream } from "../core/types";
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
