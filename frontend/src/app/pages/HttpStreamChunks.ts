import type { HttpStream } from "../core/types";

export type HTTPChunk = {
  key: string;
  streamIndex: number;
  packetId: number;
  direction: "client" | "server";
  body: string;
};

export const INITIAL_HTTP_RENDER_LIMIT = 72;

export function buildHTTPChunks(httpStream: HttpStream): HTTPChunk[] {
  if (httpStream.chunks.length > 0) {
    return httpStream.chunks.map((chunk, index) => ({
      key: `${chunk.packetId}-${chunk.direction}-${index}`,
      streamIndex: index,
      packetId: chunk.packetId,
      direction: chunk.direction,
      body: chunk.body,
    }));
  }

  const fallback: HTTPChunk[] = [];
  if (httpStream.request) {
    fallback.push({
      key: "fallback-client-0",
      streamIndex: 0,
      packetId: 0,
      direction: "client",
      body: httpStream.request,
    });
  }
  if (httpStream.response) {
    fallback.push({
      key: "fallback-server-1",
      streamIndex: fallback.length,
      packetId: 0,
      direction: "server",
      body: httpStream.response,
    });
  }
  return fallback;
}

export function filterHTTPChunks(chunks: HTTPChunk[], search: string): HTTPChunk[] {
  if (!search.trim()) return chunks;
  const query = search.toLowerCase();
  return chunks.filter((chunk) => chunk.body.toLowerCase().includes(query));
}

export function countHTTPChunkMatches(chunks: HTTPChunk[], search: string): number {
  if (!search.trim()) return 0;
  const query = search.toLowerCase();
  return chunks.reduce((sum, chunk) => sum + countMatches(chunk.body.toLowerCase(), query), 0);
}

export function exportHTTPChunks(chunks: HTTPChunk[]): string {
  return chunks
    .map(
      (chunk) =>
        `--- ${chunk.direction === "client" ? "REQUEST" : "RESPONSE"} [packet:${chunk.packetId}] ---\n${chunk.body}`,
    )
    .join("\n\n");
}

function countMatches(text: string, query: string): number {
  let count = 0;
  let index = 0;
  while (index >= 0) {
    index = text.indexOf(query, index);
    if (index >= 0) {
      count += 1;
      index += query.length;
    }
  }
  return count;
}
