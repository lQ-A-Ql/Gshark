import type { StreamLoadMeta } from "../core/types";
import { bytesToAscii, bytesToHexDump, estimatePayloadBytes, parseChunkBytes } from "../core/stream-utils";

export type RawStreamProtocol = "TCP" | "UDP";
export type RawViewMode = "ascii" | "hex" | "raw";
export type RawChunk = { packetId: number; direction: string; body: string };
export type VisibleRawChunk = RawChunk & { key: string; streamIndex: number };

export const MAX_RAW_STREAM_PREVIEW_BYTES = 4096;

export function formatRawStreamLoadMeta(protocol: RawStreamProtocol, meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return `正在解析当前 ${protocol} 流...`;
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  const overrides = meta.overrideCount && meta.overrideCount > 0 ? ` / overrides ${meta.overrideCount}` : "";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}${overrides}`;
}

export function isHexPayload(body: string): boolean {
  return /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test((body ?? "").trim());
}

export function isRawStreamChunkTruncated(body: string, mode: RawViewMode): boolean {
  const raw = (body ?? "").trim();
  if (!raw) return false;
  if (mode === "raw") {
    return raw.length > MAX_RAW_STREAM_PREVIEW_BYTES * 3;
  }
  if (isHexPayload(raw)) {
    return raw.split(":").length > MAX_RAW_STREAM_PREVIEW_BYTES;
  }
  return raw.length > MAX_RAW_STREAM_PREVIEW_BYTES;
}

export function renderRawStreamChunk(body: string, mode: RawViewMode, expanded = false): string {
  const raw = body || "";
  if (mode === "raw") {
    if (!raw) return "(empty payload)";
    if (expanded || raw.length <= MAX_RAW_STREAM_PREVIEW_BYTES * 3) {
      return raw;
    }
    return `${raw.slice(0, MAX_RAW_STREAM_PREVIEW_BYTES * 3)}\n\n... 已截断，点击查看完整 payload`;
  }

  const bytes = parseChunkBytes(raw, expanded ? Number.POSITIVE_INFINITY : MAX_RAW_STREAM_PREVIEW_BYTES);
  if (mode === "hex") {
    const rendered = bytesToHexDump(bytes);
    return expanded || !isRawStreamChunkTruncated(raw, mode)
      ? rendered
      : `${rendered}\n\n... 已截断，点击查看完整 payload`;
  }

  const rendered = bytesToAscii(bytes);
  return expanded || !isRawStreamChunkTruncated(raw, mode)
    ? rendered
    : `${rendered}\n\n... 已截断，点击查看完整 payload`;
}

export function toVisibleRawChunks(chunks: RawChunk[]): VisibleRawChunk[] {
  return chunks.map((chunk, index) => ({
    ...chunk,
    key: `${chunk.packetId}-${chunk.direction}-${index}`,
    streamIndex: index,
  }));
}

export function filterRawChunks(chunks: VisibleRawChunk[], query: string): VisibleRawChunk[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return chunks;
  return chunks.filter((chunk) => chunk.body.toLowerCase().includes(normalizedQuery));
}

export function countRawChunkMatches(chunks: VisibleRawChunk[], query: string): number {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return 0;
  return chunks.reduce((sum, chunk) => sum + countOccurrences(chunk.body, normalizedQuery), 0);
}

export function getRawDirectionLabel(direction: string): string {
  return direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端";
}

export function getRawDirectionExportLabel(direction: string): string {
  return direction === "client" ? "CLIENT -> SERVER" : "SERVER -> CLIENT";
}

export function buildRawStreamExportContent(chunks: RawChunk[]): string {
  return chunks
    .map((chunk) => `--- ${getRawDirectionExportLabel(chunk.direction)} [packet:${chunk.packetId}] ---\n${chunk.body}`)
    .join("\n\n");
}

export function buildRawStreamChunkChips(chunk: VisibleRawChunk): string[] {
  return [`packet #${chunk.packetId}`, `${estimatePayloadBytes(chunk.body)} bytes`, `chunk #${chunk.streamIndex + 1}`];
}

export function buildRawStreamDialogMeta(
  protocol: RawStreamProtocol,
  streamId: number,
  chunk: VisibleRawChunk,
  totalChunks: number,
  viewMode: RawViewMode,
) {
  return [
    { label: "协议", value: protocol },
    { label: "Stream", value: streamId },
    { label: "Packet", value: `#${chunk.packetId}` },
    { label: "方向", value: getRawDirectionLabel(chunk.direction) },
    { label: "Chunk", value: `${chunk.streamIndex + 1} / ${totalChunks}` },
    { label: "视图", value: viewMode },
    { label: "原始估算", value: `${estimatePayloadBytes(chunk.body)} bytes` },
    { label: "预览阈值", value: `${MAX_RAW_STREAM_PREVIEW_BYTES} bytes` },
  ];
}

function countOccurrences(text: string, query: string): number {
  let count = 0;
  let index = 0;
  const haystack = text.toLowerCase();
  while (index >= 0) {
    index = haystack.indexOf(query, index);
    if (index >= 0) {
      count += 1;
      index += query.length;
    }
  }
  return count;
}
