import { memo, useDeferredValue, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowLeftRight,
  ChevronLeft,
  ChevronRight,
  Download,
  Search,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { ungzip } from "pako";
import { useSentinel } from "../state/SentinelContext";
import type { StreamLoadMeta } from "../core/types";
import { StreamDecoderWorkbench } from "../components/StreamDecoderWorkbench";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

type HTTPChunk = {
  key: string;
  streamIndex: number;
  packetId: number;
  direction: "client" | "server";
  body: string;
};

type HTTPViewMode = "formatted" | "raw" | "hex";

const INITIAL_RENDER_LIMIT = 72;

export default function HttpStream() {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    httpStream,
    selectedPacket,
    streamIds,
    setActiveStream,
    persistStreamPayloads,
    streamSwitchMetrics,
  } = useSentinel();
  const [viewMode, setViewMode] = useState<HTTPViewMode>("formatted");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState(0);
  const [streamInput, setStreamInput] = useState("");
  const [renderLimit, setRenderLimit] = useState(INITIAL_RENDER_LIMIT);
  const deferredSearch = useDeferredValue(search);
  const currentIndex = streamIds.http.findIndex((id) => id === httpStream.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.http.length || 1}` : `-- / ${streamIds.http.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.http.length - 1;

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const streamId = routeStreamId >= 0 ? routeStreamId : selectedStreamId;
    if (streamId < 0 || !streamIds.http.includes(streamId) || httpStream.id >= 0) {
      return;
    }
    void setActiveStream("HTTP", streamId);
  }, [httpStream.id, location.state, selectedPacket?.streamId, setActiveStream, streamIds.http]);

  const allChunks = useMemo<HTTPChunk[]>(() => {
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
  }, [httpStream.chunks, httpStream.request, httpStream.response]);

  const displayChunks = useMemo<HTTPChunk[]>(() => {
    if (!deferredSearch.trim()) return allChunks;
    const query = deferredSearch.toLowerCase();
    return allChunks.filter((chunk) => chunk.body.toLowerCase().includes(query));
  }, [allChunks, deferredSearch]);

  const matchCount = useMemo(() => {
    if (!deferredSearch.trim()) return 0;
    const query = deferredSearch.toLowerCase();
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
  }, [deferredSearch, displayChunks]);

  const selectedIndex = Math.min(cursor, Math.max(0, displayChunks.length - 1));
  const selectedChunk = displayChunks[selectedIndex];
  const visibleChunks = useMemo(() => displayChunks.slice(0, renderLimit), [displayChunks, renderLimit]);
  const deferredVisibleChunks = useDeferredValue(visibleChunks);
  const deferredSelectedIndex = useDeferredValue(selectedIndex);

  useEffect(() => {
    setRenderLimit(INITIAL_RENDER_LIMIT);
    setCursor(0);
  }, [httpStream.id]);

  useEffect(() => {
    setStreamInput(httpStream.id >= 0 ? String(httpStream.id) : "");
  }, [httpStream.id]);

  const exportAll = () => {
    const content = allChunks
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
            HTTP 会话追踪 (stream eq {httpStream.id})
            <span className="ml-2 flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {httpStream.client} <ArrowLeftRight className="h-3 w-3" /> {httpStream.server}
            </span>
          </h1>
        </div>

        <div className="grid grid-cols-[260px_400px_220px] items-center gap-2">
          <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
            切流 last {streamSwitchMetrics.byProtocol.HTTP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.HTTP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.HTTP.p95Ms}ms / fast-path {streamSwitchMetrics.byProtocol.HTTP.cacheHitRate}%
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
              第 {ordinalLabel} 条 / stream eq {httpStream.id}
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
                if (id >= 0) {
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

          <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
            {formatLoadMeta(httpStream.loadMeta)}
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
              当前流没有可展示内容。
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              {deferredVisibleChunks.map((chunk, index) => (
                <HTTPChunkCard
                  key={chunk.key}
                  chunk={chunk}
                  viewMode={viewMode}
                  selected={index === deferredSelectedIndex}
                  onClick={() => setCursor(index)}
                />
              ))}
              {renderLimit < displayChunks.length && (
                <button
                  className="self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                  onClick={() => setRenderLimit((prev) => Math.min(prev + 180, displayChunks.length))}
                >
                  加载更多 ({renderLimit}/{displayChunks.length})
                </button>
              )}
              <StreamDecoderWorkbench
                payload={selectedChunk?.body ?? ""}
                chunkLabel={selectedChunk ? `HTTP 片段 #${selectedChunk.packetId} / ${selectedChunk.direction === "server" ? "响应" : "请求"}` : `HTTP 流 stream eq ${httpStream.id}`}
                tone="emerald"
                batchItems={allChunks.map((chunk) => ({
                  index: chunk.streamIndex,
                  payload: chunk.body,
                  label: `#${chunk.packetId || chunk.streamIndex + 1} ${chunk.direction === "server" ? "response" : "request"}`,
                }))}
                selectedBatchIndex={selectedChunk?.streamIndex ?? 0}
                onApplyDecodedBatch={(patches) => persistStreamPayloads("HTTP", httpStream.id, patches)}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 HTTP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}`;
}

const HTTPChunkCard = memo(function HTTPChunkCard({
  chunk,
  viewMode,
  selected,
  onClick,
}: {
  chunk: HTTPChunk;
  viewMode: HTTPViewMode;
  selected: boolean;
  onClick: () => void;
}) {
  const rendered = useMemo(() => {
    if (viewMode === "hex") {
      return toHexDump(chunk.body);
    }
    if (viewMode === "formatted") {
      return formatHTTPForDisplay(chunk.body);
    }
    return chunk.body;
  }, [chunk.body, viewMode]);

  const isClient = chunk.direction === "client";
  return (
    <div
      onClick={onClick}
      className={cn(
        "cursor-pointer rounded-md border px-3 py-2 font-mono text-xs leading-5",
        isClient ? "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
        selected && "ring-2 ring-blue-300",
      )}
    >
      <div className="mb-1 flex items-center justify-between text-[11px] font-semibold opacity-80">
        <span>{isClient ? "Request ->" : "<- Response"}</span>
        <span>packet #{chunk.packetId}</span>
      </div>
      <pre className="whitespace-pre-wrap break-all">{rendered}</pre>
    </div>
  );
});

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
