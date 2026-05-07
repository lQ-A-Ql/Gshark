import type { BinaryStream, HttpStream, StreamLoadMeta, StreamSwitchMetrics, StreamSwitchStat } from "../core/types";

export const EMPTY_HTTP_STREAM: HttpStream = {
  id: -1,
  client: "",
  server: "",
  request: "",
  response: "",
  chunks: [],
};

export const EMPTY_BINARY_STREAM: BinaryStream = {
  id: -1,
  protocol: "TCP",
  from: "",
  to: "",
  chunks: [],
  nextCursor: 0,
  totalChunks: 0,
  hasMore: false,
};

export const EMPTY_SWITCH_STAT: StreamSwitchStat = {
  count: 0,
  lastMs: 0,
  p50Ms: 0,
  p95Ms: 0,
  cacheHitRate: 0,
};

export const EMPTY_SWITCH_METRICS: StreamSwitchMetrics = {
  overall: { ...EMPTY_SWITCH_STAT },
  byProtocol: {
    HTTP: { ...EMPTY_SWITCH_STAT },
    TCP: { ...EMPTY_SWITCH_STAT },
    UDP: { ...EMPTY_SWITCH_STAT },
  },
};

export const SWITCH_SAMPLE_LIMIT = 300;

export function buildSwitchStat(values: number[], hitCount: number): StreamSwitchStat {
  const count = values.length;
  if (count === 0) return { ...EMPTY_SWITCH_STAT };
  const lastMs = Number(values[count - 1].toFixed(1));
  const p50Ms = calcPercentile(values, 50);
  const p95Ms = calcPercentile(values, 95);
  const cacheHitRate = Number(((hitCount / count) * 100).toFixed(1));
  return { count, lastMs, p50Ms, p95Ms, cacheHitRate };
}

export function isFastPathLoad(meta?: StreamLoadMeta): boolean {
  if (!meta) return false;
  return Boolean(meta.cacheHit || meta.indexHit || meta.source === "memory" || meta.source === "cache");
}

export function markCachedLoad<T extends HttpStream | BinaryStream>(stream: T): T {
  return {
    ...stream,
    loadMeta: {
      ...(stream.loadMeta ?? {}),
      source: "cache",
      cacheHit: true,
    },
  };
}

export function buildLoadingHttpStream(streamId: number): HttpStream {
  return {
    id: streamId,
    client: "",
    server: "",
    request: "",
    response: "",
    chunks: [],
    loadMeta: {
      source: "loading",
      loading: true,
    },
  };
}

export function buildLoadingBinaryStream(protocol: "TCP" | "UDP", streamId: number): BinaryStream {
  return {
    id: streamId,
    protocol,
    from: "",
    to: "",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: {
      source: "loading",
      loading: true,
    },
  };
}

export function prettySize(bytes: number) {
  const mb = bytes / 1024 / 1024;
  return `${mb.toFixed(1)} MB`;
}

export function applyStreamChunkPatches<T extends HttpStream | BinaryStream>(
  stream: T,
  patches: Array<{ index: number; body: string }>,
): T {
  if (patches.length === 0 || stream.chunks.length === 0) return stream;

  const patchMap = new Map<number, string>();
  for (const patch of patches) {
    if (patch.index < 0) continue;
    patchMap.set(patch.index, patch.body);
  }
  if (patchMap.size === 0) return stream;

  const nextChunks = stream.chunks.map((chunk, index) =>
    patchMap.has(index) ? { ...chunk, body: patchMap.get(index) ?? chunk.body } : chunk,
  );

  if ("request" in stream && "response" in stream) {
    return {
      ...stream,
      chunks: nextChunks,
      request: nextChunks
        .filter((chunk) => chunk.direction === "client")
        .map((chunk) => chunk.body)
        .join(""),
      response: nextChunks
        .filter((chunk) => chunk.direction === "server")
        .map((chunk) => chunk.body)
        .join(""),
    };
  }

  return {
    ...stream,
    chunks: nextChunks,
  };
}

function calcPercentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil((percentile / 100) * sorted.length) - 1));
  return Number(sorted[idx].toFixed(1));
}
