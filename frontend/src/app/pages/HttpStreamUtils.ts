import { ungzip } from "pako";
import type { StreamLoadMeta } from "../core/types";

export type HTTPViewMode = "formatted" | "raw" | "hex";

export const MAX_HTTP_PREVIEW_CHARS = 6000;

export function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 HTTP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  const overrides = meta.overrideCount && meta.overrideCount > 0 ? ` / overrides ${meta.overrideCount}` : "";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}${overrides}`;
}

export function renderHTTPChunk(body: string, viewMode: HTTPViewMode, expanded = false): string {
  let rendered = body;
  if (viewMode === "hex") {
    rendered = toHexDump(body);
  } else if (viewMode === "formatted") {
    rendered = formatHTTPForDisplay(body);
  }
  if (expanded || rendered.length <= MAX_HTTP_PREVIEW_CHARS) {
    return rendered;
  }
  return `${rendered.slice(0, MAX_HTTP_PREVIEW_CHARS)}\n\n... 已截断，点击查看完整 payload`;
}

export function isHTTPChunkTruncated(body: string, viewMode: HTTPViewMode): boolean {
  return renderHTTPChunk(body, viewMode, true).length > MAX_HTTP_PREVIEW_CHARS;
}

export function toHexDump(text: string): string {
  if (!text) return "(empty)";
  const bytes = Array.from(new TextEncoder().encode(text));
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  return lines.join("\n");
}

export function estimateTextBytes(text: string): number {
  return new TextEncoder().encode(text || "").length;
}

export function formatHTTPForDisplay(text: string): string {
  if (!text) return "";
  const normalized = text.replace(/\r\n/g, "\n");
  const splitAt = normalized.indexOf("\n\n");
  if (splitAt < 0) return tryFormatBody(normalized.trim(), "");

  const headers = normalized.slice(0, splitAt).trim();
  const body = normalized.slice(splitAt + 2).trim();
  const formattedBody = tryFormatBody(body, headers);
  return `${headers}\n\n${formattedBody}`;
}

export function tryFormatBody(body: string, headers: string): string {
  if (!body) return body;

  const gunzipped = tryGunzipBody(body, headers);
  const effectiveBody = gunzipped ?? body;

  const maybeJSON = effectiveBody.trim();
  if (
    (maybeJSON.startsWith("{") && maybeJSON.endsWith("}")) ||
    (maybeJSON.startsWith("[") && maybeJSON.endsWith("]"))
  ) {
    try {
      return JSON.stringify(JSON.parse(maybeJSON), null, 2);
    } catch {
      // keep original text when JSON parse fails
    }
  }

  const maybeHTML = maybeJSON.toLowerCase();
  if (maybeHTML.includes("<html") || maybeHTML.includes("<!doctype html") || maybeHTML.includes("<body")) {
    return prettyHtml(maybeJSON);
  }

  return effectiveBody;
}

export function tryGunzipBody(body: string, headers: string): string | null {
  const looksGzip = /content-encoding\s*:\s*gzip/i.test(headers);
  const bytes = parsePossibleBinaryBody(body);
  if (bytes.length < 3) return null;
  const hasMagic = bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (!looksGzip && !hasMagic) return null;

  try {
    const decoded = ungzip(Uint8Array.from(bytes), { to: "string" });
    return typeof decoded === "string" ? decoded : String(decoded);
  } catch {
    return null;
  }
}

export function parsePossibleBinaryBody(body: string): number[] {
  const raw = body.trim();
  if (!raw) return [];

  if (/^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})+$/.test(raw)) {
    return raw
      .split(":")
      .map((part) => Number.parseInt(part, 16))
      .filter((v) => Number.isFinite(v));
  }

  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    const out: number[] = [];
    for (let i = 0; i < raw.length; i += 2) {
      out.push(Number.parseInt(raw.slice(i, i + 2), 16));
    }
    return out;
  }

  return Array.from(new TextEncoder().encode(raw));
}

export function prettyHtml(html: string): string {
  const lines = html
    .replace(/>\s+</g, ">\n<")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  let depth = 0;
  const out: string[] = [];
  for (const line of lines) {
    const closing = /^<\//.test(line);
    const selfClosing = /\/>$/.test(line) || /^<!/.test(line) || /^<\?/.test(line);
    if (closing) depth = Math.max(0, depth - 1);
    out.push(`${"  ".repeat(depth)}${line}`);
    const opening = /^<[^!/][^>]*>$/.test(line) && !closing && !selfClosing && !/<\/[^>]+>$/.test(line);
    if (opening) depth += 1;
  }
  return out.join("\n");
}
