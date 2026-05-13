import type { BinaryStream, HttpStream } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asHttpStream(input: unknown): HttpStream {
  const payload = asPlainObject(input) ?? {};
  const chunks = asStreamChunks(payload.chunks);
  const fallbackChunks = chunks.length
    ? chunks
    : [
        ...(String(payload.request ?? "")
          ? [{ packetId: 0, direction: "client" as const, body: String(payload.request ?? "") }]
          : []),
        ...(String(payload.response ?? "")
          ? [{ packetId: 0, direction: "server" as const, body: String(payload.response ?? "") }]
          : []),
      ];

  return {
    id: Number(payload.stream_id ?? 1),
    client: String(payload.from ?? ""),
    server: String(payload.to ?? ""),
    request: String(payload.request ?? ""),
    response: String(payload.response ?? ""),
    chunks: fallbackChunks,
    loadMeta: asStreamLoadMeta(payload.load_meta),
  };
}

export function asBinaryStream(input: unknown, protocol: "TCP" | "UDP"): BinaryStream {
  const payload = asPlainObject(input) ?? {};
  const chunks = asStreamChunks(payload.chunks);
  return {
    id: Number(payload.stream_id ?? 1),
    protocol,
    from: String(payload.from ?? ""),
    to: String(payload.to ?? ""),
    chunks,
    nextCursor: Number(payload.next_cursor ?? chunks.length),
    totalChunks: Number(payload.total ?? chunks.length),
    hasMore: Boolean(payload.has_more),
    loadMeta: asStreamLoadMeta(payload.load_meta),
  };
}

function asStreamChunks(input: unknown): HttpStream["chunks"] {
  return asArray(input).map((value) => {
    const chunk = asPlainObject(value) ?? {};
    return {
      packetId: Number(chunk.packet_id ?? 0),
      direction: chunk.direction === "server" ? "server" : "client",
      body: String(chunk.body ?? ""),
    };
  });
}

function asStreamLoadMeta(input: unknown): HttpStream["loadMeta"] {
  const payload = asPlainObject(input);
  if (!payload) {
    return undefined;
  }
  return {
    source: String(payload.source ?? "").trim() || undefined,
    loading: Boolean(payload.loading),
    cacheHit: Boolean(payload.cache_hit),
    indexHit: Boolean(payload.index_hit),
    fileFallback: Boolean(payload.file_fallback),
    tsharkMs: Number(payload.tshark_ms ?? 0) || 0,
    overrideCount: Number(payload.override_count ?? 0) || undefined,
  };
}
