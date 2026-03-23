import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowLeftRight,
  ChevronLeft,
  ChevronRight,
  Download,
  Search,
} from "lucide-react";
import { useNavigate } from "react-router";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { ungzip } from "pako";
import { useSentinel } from "../state/SentinelContext";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

export default function HttpStream() {
  const navigate = useNavigate();
  const { httpStream, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();
  const [viewMode, setViewMode] = useState<"formatted" | "raw" | "hex">("formatted");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState(0);
  const [streamInput, setStreamInput] = useState("");
  const [renderLimit, setRenderLimit] = useState(160);
  const currentIndex = streamIds.http.findIndex((id) => id === httpStream.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.http.length || 1}` : `-- / ${streamIds.http.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.http.length - 1;

  const displayChunks = useMemo(() => {
    const base =
      httpStream.chunks.length > 0
        ? httpStream.chunks
        : [
            ...(httpStream.request ? [{ packetId: 0, direction: "client" as const, body: httpStream.request }] : []),
            ...(httpStream.response ? [{ packetId: 0, direction: "server" as const, body: httpStream.response }] : []),
          ];

    if (!search.trim()) return base;
    const query = search.toLowerCase();
    return base.filter((chunk) => chunk.body.toLowerCase().includes(query));
  }, [httpStream.chunks, httpStream.request, httpStream.response, search]);

  const matchCount = useMemo(() => {
    if (!search.trim()) return 0;
    const query = search.toLowerCase();
    return displayChunks.reduce((sum, chunk) => {
      let count = 0;
      let idx = 0;
      const text = chunk.body.toLowerCase();
      while (idx >= 0) {
        idx = text.indexOf(query, idx);
        if (idx >= 0) {
          count += 1;
          idx += query.length;
        }
      }
      return sum + count;
    }, 0);
  }, [displayChunks, search]);

  const selectedIndex = Math.min(cursor, Math.max(0, displayChunks.length - 1));
  const visibleChunks = useMemo(() => displayChunks.slice(0, renderLimit), [displayChunks, renderLimit]);

  useEffect(() => {
    setRenderLimit(160);
  }, [httpStream.id]);

  const exportAll = () => {
    const content = displayChunks
      .map((chunk) => `--- ${chunk.direction === "client" ? "REQUEST" : "RESPONSE"} [packet:${chunk.packetId}] ---\n${chunk.body}`)
      .join("\n\n");
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `http-stream-${httpStream.id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-background text-sm text-foreground">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-4 py-2">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="rounded p-1 text-foreground transition-colors hover:bg-accent"
            title="返回上一页"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div className="h-4 w-px bg-border" />
          <h1 className="flex items-center gap-2 font-semibold text-foreground">
            HTTP 会话时间线 (Stream: {httpStream.id})
            <span className="ml-2 flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {httpStream.client} <ArrowLeftRight className="h-3 w-3" /> {httpStream.server}
            </span>
          </h1>
        </div>

        <div className="grid grid-cols-[260px_400px_220px] items-center gap-2">
          <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
            切流 last {streamSwitchMetrics.byProtocol.HTTP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.HTTP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.HTTP.p95Ms}ms / cache {streamSwitchMetrics.byProtocol.HTTP.cacheHitRate}%
          </div>
          <div className="grid h-full grid-cols-[28px_minmax(220px,1fr)_28px_72px] items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs">
            <button
              onClick={() => {
                if (!hasPrev) return;
                void setActiveStream("HTTP", streamIds.http[currentIndex - 1]);
              }}
              disabled={!hasPrev}
              className="rounded border border-border p-0.5 text-muted-foreground hover:bg-accent disabled:opacity-40"
              title={`HTTP 流总数: ${streamIds.http.length}`}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span className="px-1 text-center font-mono" title={`HTTP 流总数: ${streamIds.http.length}`}>
              第 {ordinalLabel} 条 · stream eq {httpStream.id}
            </span>
            <button
              onClick={() => {
                if (!hasNext) return;
                void setActiveStream("HTTP", streamIds.http[currentIndex + 1]);
              }}
              disabled={!hasNext}
              className="rounded border border-border p-0.5 text-muted-foreground hover:bg-accent disabled:opacity-40"
              title={`HTTP 流总数: ${streamIds.http.length}`}
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
            <input
              value={streamInput}
              onChange={(event) => setStreamInput(event.target.value.replace(/[^0-9]/g, ""))}
              onKeyDown={(event) => {
                if (event.key !== "Enter") return;
                const id = Number(streamInput);
                if (id > 0) {
                  void setActiveStream("HTTP", id);
                }
              }}
              className="w-16 rounded border border-border bg-card px-1 py-0.5 text-center font-mono outline-none"
              placeholder="stream"
              title={`HTTP 流总数: ${streamIds.http.length}`}
            />
          </div>
          <div className="flex justify-self-start rounded-md border border-border bg-accent p-0.5">
            <button
              onClick={() => setViewMode("formatted")}
              className={cn(
                "rounded-sm px-2 py-0.5 text-xs transition-colors",
                viewMode === "formatted" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              Formatted
            </button>
            <button
              onClick={() => setViewMode("raw")}
              className={cn(
                "rounded-sm px-2 py-0.5 text-xs transition-colors",
                viewMode === "raw" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              Raw
            </button>
            <button
              onClick={() => setViewMode("hex")}
              className={cn(
                "rounded-sm px-2 py-0.5 text-xs transition-colors",
                viewMode === "hex" ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              Hex
            </button>
          </div>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex shrink-0 items-center justify-between border-b border-border bg-card px-4 py-2 shadow-sm">
          <div className="flex items-center gap-2">
            <div className="flex w-72 items-center overflow-hidden rounded-md border border-border bg-background shadow-sm transition-colors focus-within:border-blue-500">
              <Search className="ml-2 h-4 w-4 text-muted-foreground" />
              <input
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value);
                  setCursor(0);
                }}
                type="text"
                className="flex-1 border-none bg-transparent px-2 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
                placeholder="搜索流内容..."
              />
            </div>
            <button
              className="rounded-md border border-border bg-background p-1.5 text-muted-foreground shadow-sm hover:bg-accent hover:text-foreground"
              onClick={() => setCursor((prev) => Math.max(prev - 1, 0))}
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              className="rounded-md border border-border bg-background p-1.5 text-muted-foreground shadow-sm hover:bg-accent hover:text-foreground"
              onClick={() => setCursor((prev) => Math.min(prev + 1, Math.max(0, displayChunks.length - 1)))}
            >
              <ChevronRight className="h-4 w-4" />
            </button>
            <span className="px-2 text-xs font-medium text-muted-foreground">{matchCount} 匹配</span>
          </div>

          <button
            onClick={exportAll}
            className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent"
          >
            <Download className="h-3.5 w-3.5" /> 导出流文本
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4">
          {displayChunks.length === 0 ? (
            <div className="rounded-md border border-border bg-card px-4 py-3 text-xs text-muted-foreground">
              当前流无可展示内容。
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {visibleChunks.map((chunk, index) => {
                const selected = index === selectedIndex;
                const isClient = chunk.direction === "client";
                return (
                  <div
                    key={`${chunk.packetId}-${index}`}
                    className={cn(
                      "rounded-md border px-3 py-2 font-mono text-xs leading-5",
                      isClient ? "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
                      selected && "ring-2 ring-blue-300",
                    )}
                  >
                    <div className="mb-1 flex items-center justify-between text-[11px] font-semibold opacity-80">
                      <span>{isClient ? "Request ->" : "<- Response"}</span>
                      <span>packet #{chunk.packetId}</span>
                    </div>
                    <pre className="whitespace-pre-wrap break-all">
                      {viewMode === "hex"
                        ? toHexDump(chunk.body)
                        : viewMode === "formatted"
                          ? formatHTTPForDisplay(chunk.body)
                          : chunk.body}
                    </pre>
                  </div>
                );
              })}
              {renderLimit < displayChunks.length && (
                <button
                  className="self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                  onClick={() => setRenderLimit((prev) => Math.min(prev + 240, displayChunks.length))}
                >
                  加载更多 ({renderLimit}/{displayChunks.length})
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function toHexDump(text: string): string {
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

function formatHTTPForDisplay(text: string): string {
  if (!text) return "";
  const normalized = text.replace(/\r\n/g, "\n");
  const splitAt = normalized.indexOf("\n\n");
  if (splitAt < 0) return tryFormatBody(normalized.trim(), "");

  const headers = normalized.slice(0, splitAt).trim();
  const body = normalized.slice(splitAt + 2).trim();
  const formattedBody = tryFormatBody(body, headers);
  return `${headers}\n\n${formattedBody}`;
}

function tryFormatBody(body: string, headers: string): string {
  if (!body) return body;

  const gunzipped = tryGunzipBody(body, headers);
  const effectiveBody = gunzipped ?? body;

  const maybeJSON = effectiveBody.trim();
  if ((maybeJSON.startsWith("{") && maybeJSON.endsWith("}")) || (maybeJSON.startsWith("[") && maybeJSON.endsWith("]"))) {
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

function tryGunzipBody(body: string, headers: string): string | null {
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

function parsePossibleBinaryBody(body: string): number[] {
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

function prettyHtml(html: string): string {
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
