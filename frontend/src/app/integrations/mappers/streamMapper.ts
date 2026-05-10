import type { BinaryStream, HttpStream } from "../../core/types";

export function asHttpStream(input: any): HttpStream {
  const chunks = asStreamChunks(input.chunks);
  const fallbackChunks = chunks.length
    ? chunks
    : [
        ...(String(input.request ?? "")
          ? [{ packetId: 0, direction: "client" as const, body: String(input.request ?? "") }]
          : []),
        ...(String(input.response ?? "")
          ? [{ packetId: 0, direction: "server" as const, body: String(input.response ?? "") }]
          : []),
      ];

  return {
    id: Number(input.stream_id ?? 1),
    client: String(input.from ?? ""),
    server: String(input.to ?? ""),
    request: String(input.request ?? ""),
    response: String(input.response ?? ""),
    chunks: fallbackChunks,
    loadMeta: asStreamLoadMeta(input.load_meta),
  };
}

export function asBinaryStream(input: any, protocol: "TCP" | "UDP"): BinaryStream {
  const chunks = asStreamChunks(input.chunks);
  return {
    id: Number(input.stream_id ?? 1),
    protocol,
    from: String(input.from ?? ""),
    to: String(input.to ?? ""),
    chunks,
    nextCursor: Number(input.next_cursor ?? chunks.length),
    totalChunks: Number(input.total ?? chunks.length),
    hasMore: Boolean(input.has_more),
    loadMeta: asStreamLoadMeta(input.load_meta),
  };
}

function asStreamChunks(input: any): HttpStream["chunks"] {
  return Array.isArray(input)
    ? input.map((chunk: any) => ({
        packetId: Number(chunk.packet_id ?? 0),
        direction: chunk.direction === "server" ? "server" : "client",
        body: String(chunk.body ?? ""),
      }))
    : [];
}

function asStreamLoadMeta(input: any): HttpStream["loadMeta"] {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  return {
    source: String(input.source ?? "").trim() || undefined,
    loading: Boolean(input.loading),
    cacheHit: Boolean(input.cache_hit),
    indexHit: Boolean(input.index_hit),
    fileFallback: Boolean(input.file_fallback),
    tsharkMs: Number(input.tshark_ms ?? 0) || 0,
    overrideCount: Number(input.override_count ?? 0) || undefined,
  };
}
