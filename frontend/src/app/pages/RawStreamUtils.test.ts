import { describe, expect, it } from "vitest";
import {
  buildRawStreamChunkChips,
  buildRawStreamDialogMeta,
  buildRawStreamExportContent,
  countRawChunkMatches,
  filterRawChunks,
  formatRawStreamLoadMeta,
  isHexPayload,
  isRawStreamChunkTruncated,
  MAX_RAW_STREAM_PREVIEW_BYTES,
  renderRawStreamChunk,
  toVisibleRawChunks,
} from "./RawStreamUtils";

describe("RawStreamUtils", () => {
  it("formats TCP and UDP load metadata", () => {
    expect(formatRawStreamLoadMeta("TCP")).toBe("来源 unknown");
    expect(formatRawStreamLoadMeta("UDP", { loading: true })).toBe("正在解析当前 UDP 流...");
    expect(
      formatRawStreamLoadMeta("TCP", {
        source: "backend",
        cacheHit: true,
        indexHit: false,
        fileFallback: true,
        tsharkMs: 18,
        overrideCount: 3,
      }),
    ).toBe("来源 backend / cache yes / index no / fallback yes / tshark 18ms / overrides 3");
  });

  it("detects colon-separated hex payloads", () => {
    expect(isHexPayload("47:45:54")).toBe(true);
    expect(isHexPayload("GET")).toBe(false);
  });

  it("renders ascii and hex views from stream payload bytes", () => {
    expect(renderRawStreamChunk("47:45:54", "ascii", true)).toBe("GET");
    expect(renderRawStreamChunk("47:45:54", "hex", true)).toBe(
      "0000  47 45 54                                         GET",
    );
  });

  it("keeps expanded raw payloads complete while truncating collapsed previews", () => {
    const body = "x".repeat(MAX_RAW_STREAM_PREVIEW_BYTES * 3 + 1);

    expect(renderRawStreamChunk(body, "raw", true)).toBe(body);
    expect(renderRawStreamChunk(body, "raw", false)).toContain("已截断");
    expect(isRawStreamChunkTruncated(body, "raw")).toBe(true);
  });

  it("builds visible chunks, search counts, export text, chips, and dialog metadata", () => {
    const chunks = toVisibleRawChunks([
      { packetId: 7, direction: "client", body: "hello hello" },
      { packetId: 8, direction: "server", body: "world" },
    ]);

    expect(chunks[0]?.key).toBe("7-client-0");
    expect(filterRawChunks(chunks, "world")).toHaveLength(1);
    expect(countRawChunkMatches(chunks, "hello")).toBe(2);
    expect(buildRawStreamExportContent(chunks)).toContain("CLIENT -> SERVER");
    expect(buildRawStreamChunkChips(chunks[0]!)).toEqual(["packet #7", "11 bytes", "chunk #1"]);
    expect(buildRawStreamDialogMeta("TCP", 3, chunks[0]!, 2, "ascii")).toContainEqual({
      label: "方向",
      value: "客户端 -> 服务端",
    });
  });
});
