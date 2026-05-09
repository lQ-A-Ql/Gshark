import { gzip } from "pako";
import { describe, expect, it } from "vitest";
import {
  formatHTTPForDisplay,
  formatLoadMeta,
  isHTTPChunkTruncated,
  parsePossibleBinaryBody,
  renderHTTPChunk,
  toHexDump,
  tryGunzipBody,
} from "./HttpStreamUtils";

describe("HttpStreamUtils", () => {
  it("formats load metadata with cache and tshark details", () => {
    expect(formatLoadMeta()).toBe("来源 unknown");
    expect(formatLoadMeta({ loading: true })).toBe("正在解析当前 HTTP 流...");
    expect(
      formatLoadMeta({
        source: "backend",
        cacheHit: true,
        indexHit: false,
        fileFallback: true,
        tsharkMs: 42,
        overrideCount: 2,
      }),
    ).toBe("来源 backend / cache yes / index no / fallback yes / tshark 42ms / overrides 2");
  });

  it("pretty prints JSON HTTP bodies", () => {
    const formatted = formatHTTPForDisplay(
      'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true,"count":2}',
    );

    expect(formatted).toContain("HTTP/1.1 200 OK");
    expect(formatted).toContain('"ok": true');
    expect(formatted).toContain('"count": 2');
  });

  it("keeps raw view unchanged and truncates only collapsed previews", () => {
    const body = "x".repeat(6100);

    expect(renderHTTPChunk(body, "raw", true)).toBe(body);
    expect(renderHTTPChunk(body, "raw", false)).toContain("已截断");
    expect(isHTTPChunkTruncated(body, "raw")).toBe(true);
  });

  it("renders a stable hex dump", () => {
    expect(toHexDump("GET")).toBe("0000  47 45 54                                         GET");
    expect(renderHTTPChunk("GET", "hex", true)).toContain("47 45 54");
  });

  it("parses hex, colon hex, and text bodies into bytes", () => {
    expect(parsePossibleBinaryBody("1f8b08")).toEqual([0x1f, 0x8b, 0x08]);
    expect(parsePossibleBinaryBody("1f:8b:08")).toEqual([0x1f, 0x8b, 0x08]);
    expect(parsePossibleBinaryBody("OK")).toEqual([0x4f, 0x4b]);
  });

  it("gunzips payloads when headers or magic bytes indicate gzip", () => {
    const compressedHex = Array.from(gzip("hello"))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    expect(tryGunzipBody(compressedHex, "Content-Encoding: gzip")).toBe("hello");
    expect(tryGunzipBody(compressedHex, "")).toBe("hello");
  });
});
