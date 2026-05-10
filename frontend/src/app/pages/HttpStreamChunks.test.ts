import { describe, expect, it } from "vitest";
import type { HttpStream } from "../core/types";
import { buildHTTPChunks, countHTTPChunkMatches, exportHTTPChunks, filterHTTPChunks } from "./HttpStreamChunks";

function stream(overrides: Partial<HttpStream>): HttpStream {
  return {
    id: 7,
    client: "10.0.0.1:1234",
    server: "10.0.0.2:80",
    request: "",
    response: "",
    chunks: [],
    ...overrides,
  };
}

describe("HttpStreamChunks", () => {
  it("builds chunks from packet chunks before fallback request and response", () => {
    expect(
      buildHTTPChunks(
        stream({
          request: "fallback request",
          chunks: [{ packetId: 3, direction: "server", body: "HTTP/1.1 200 OK" }],
        }),
      ),
    ).toMatchObject([{ key: "3-server-0", streamIndex: 0, packetId: 3, direction: "server" }]);
  });

  it("builds fallback request and response chunks", () => {
    expect(buildHTTPChunks(stream({ request: "GET /", response: "HTTP/1.1 200 OK" }))).toMatchObject([
      { key: "fallback-client-0", streamIndex: 0, direction: "client" },
      { key: "fallback-server-1", streamIndex: 1, direction: "server" },
    ]);
  });

  it("filters, counts matches, and exports stable stream text", () => {
    const chunks = buildHTTPChunks(
      stream({
        chunks: [
          { packetId: 1, direction: "client", body: "GET /alpha?q=alpha" },
          { packetId: 2, direction: "server", body: "HTTP/1.1 404" },
        ],
      }),
    );

    expect(filterHTTPChunks(chunks, "ALPHA")).toHaveLength(1);
    expect(countHTTPChunkMatches(chunks, "alpha")).toBe(2);
    expect(exportHTTPChunks(chunks)).toContain("--- REQUEST [packet:1] ---");
  });
});
