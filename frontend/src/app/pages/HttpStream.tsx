import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeftRight,
  Download,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { ungzip } from "pako";
import { cn } from "../components/ui/utils";
import { StreamChunkCard, StreamCurrentChunkPanel, StreamNavigator, StreamPayloadDialog, StreamSearchBar, ViewModeToggle, WorkbenchChip, WorkbenchTitleBar } from "../components/stream/StreamWorkbench";
import { useSentinel } from "../state/SentinelContext";
import type { StreamLoadMeta } from "../core/types";
import { downloadText } from "../utils/browserFile";

type HTTPChunk = {
  key: string;
  streamIndex: number;
  packetId: number;
  direction: "client" | "server";
  body: string;
};

type HTTPViewMode = "formatted" | "raw" | "hex";

const INITIAL_RENDER_LIMIT = 72;
const MAX_HTTP_PREVIEW_CHARS = 6000;

export default function HttpStream() {
  const navigate = useNavigate();
  const location = useLocation();
  const {
    httpStream,
    selectedPacket,
    streamIds,
    setActiveStream,
    streamSwitchMetrics,
  } = useSentinel();
  const [viewMode, setViewMode] = useState<HTTPViewMode>("formatted");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState(0);
  const [streamInput, setStreamInput] = useState("");
  const [renderLimit, setRenderLimit] = useState(INITIAL_RENDER_LIMIT);
  const [expandedChunk, setExpandedChunk] = useState<HTTPChunk | null>(null);
  const consumedRouteStreamIdRef = useRef<number | null>(null);
  const deferredSearch = useDeferredValue(search);
  const currentIndex = streamIds.http.findIndex((id) => id === httpStream.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.http.length || 1}` : `-- / ${streamIds.http.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.http.length - 1;

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const hasPendingRouteStream = routeStreamId >= 0 && routeStreamId !== consumedRouteStreamIdRef.current;
    const streamId = hasPendingRouteStream ? routeStreamId : httpStream.id < 0 ? selectedStreamId : -1;
    if (streamId < 0 || !streamIds.http.includes(streamId) || httpStream.id === streamId) {
      return;
    }
    if (hasPendingRouteStream) {
      consumedRouteStreamIdRef.current = routeStreamId;
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
  const selectedChunkRendered = useMemo(() => {
    if (!selectedChunk) return "";
    if (viewMode === "hex") {
      return renderHTTPChunk(selectedChunk.body, viewMode, false);
    }
    if (viewMode === "formatted") {
      return renderHTTPChunk(selectedChunk.body, viewMode, false);
    }
    return renderHTTPChunk(selectedChunk.body, viewMode, false);
  }, [selectedChunk, viewMode]);

  useEffect(() => {
    setRenderLimit(INITIAL_RENDER_LIMIT);
    setCursor(0);
    setExpandedChunk(null);
  }, [httpStream.id]);

  useEffect(() => {
    setStreamInput(httpStream.id >= 0 ? String(httpStream.id) : "");
  }, [httpStream.id]);

  const exportAll = () => {
    const content = allChunks
      .map((chunk) => `--- ${chunk.direction === "client" ? "REQUEST" : "RESPONSE"} [packet:${chunk.packetId}] ---\n${chunk.body}`)
      .join("\n\n");
    downloadText(`http-stream-${httpStream.id}.txt`, content);
  };

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.26),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <WorkbenchTitleBar
        onBack={() => navigate(-1)}
        title={`HTTP 会话追踪 (stream eq ${httpStream.id})`}
        subtitle={(
          <span className="flex min-w-0 items-center gap-1 font-mono">
            <span className="truncate">{httpStream.client}</span>
            <ArrowLeftRight className="h-3 w-3 shrink-0" />
            <span className="truncate">{httpStream.server}</span>
          </span>
        )}
        meta={(
          <WorkbenchChip className="max-w-[300px] truncate">
            切流 last {streamSwitchMetrics.byProtocol.HTTP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.HTTP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.HTTP.p95Ms}ms / fast-path {streamSwitchMetrics.byProtocol.HTTP.cacheHitRate}%
          </WorkbenchChip>
        )}
        actions={(
          <>
            <StreamNavigator
              protocolLabel="HTTP"
              ordinalLabel={ordinalLabel}
              streamId={httpStream.id}
              streamTotal={streamIds.http.length}
              streamInput={streamInput}
              onStreamInputChange={setStreamInput}
              onSubmitStream={() => {
                const id = Number(streamInput);
                if (id >= 0) void setActiveStream("HTTP", id);
              }}
              onPrev={() => {
                if (hasPrev) void setActiveStream("HTTP", streamIds.http[currentIndex - 1]);
              }}
              onNext={() => {
                if (hasNext) void setActiveStream("HTTP", streamIds.http[currentIndex + 1]);
              }}
              hasPrev={hasPrev}
              hasNext={hasNext}
            />
            <ViewModeToggle<HTTPViewMode>
              label="视图"
              value={viewMode}
              onChange={setViewMode}
              options={[
                { value: "formatted", label: "Formatted" },
                { value: "raw", label: "Raw" },
                { value: "hex", label: "Hex" },
              ]}
              className="py-1"
            />
          </>
        )}
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex shrink-0 items-center justify-between border-b border-border bg-card px-4 py-2 shadow-sm">
          <StreamSearchBar
            value={search}
            onChange={(value) => {
              setSearch(value);
              setCursor(0);
            }}
            onPrev={() => setCursor((prev) => Math.max(prev - 1, 0))}
            onNext={() => setCursor((prev) => Math.min(prev + 1, Math.max(0, displayChunks.length - 1)))}
            matchCount={matchCount}
            resultCount={displayChunks.length}
            currentIndex={selectedIndex}
          />

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
            <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]">
              <div className="flex min-h-0 flex-col gap-4">
                {deferredVisibleChunks.map((chunk, index) => (
                  <StreamChunkCard
                    key={chunk.key}
                    directionLabel={chunk.direction === "client" ? "Request ->" : "<- Response"}
                    packetId={chunk.packetId}
                    rendered={renderHTTPChunk(chunk.body, viewMode, false)}
                    highlight={deferredSearch}
                    tone={chunk.direction === "client" ? "border-rose-500/30 bg-rose-500/10 text-rose-700" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700"}
                    selected={index === deferredSelectedIndex}
                    onSelect={() => setCursor(index)}
                    onOpen={() => setExpandedChunk(chunk)}
                    truncated={isHTTPChunkTruncated(chunk.body, viewMode)}
                    minHeight="min-h-0"
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
              </div>
              <div className="space-y-4 xl:sticky xl:top-0">
                <StreamCurrentChunkPanel
                  description="按当前视图模式同步预览选中的 HTTP 请求/响应"
                  badge={selectedChunk ? (
                    <span className={cn(
                      "rounded-full border px-2.5 py-1 text-[11px] font-semibold shadow-sm",
                      selectedChunk.direction === "client"
                        ? "border-rose-200 bg-rose-50 text-rose-700"
                        : "border-emerald-200 bg-emerald-50 text-emerald-700",
                    )}>
                      {selectedChunk.direction === "client" ? "请求" : "响应"}
                    </span>
                  ) : undefined}
                  chips={selectedChunk ? [
                    `packet #${selectedChunk.packetId}`,
                    `stream-index ${selectedChunk.streamIndex}`,
                    `${estimateTextBytes(selectedChunk.body)} bytes`,
                  ] : []}
                  content={selectedChunk ? selectedChunkRendered || "(empty)" : null}
                  highlight={deferredSearch}
                  showOpenButton={selectedChunk ? isHTTPChunkTruncated(selectedChunk.body, viewMode) : false}
                  onOpen={() => selectedChunk && setExpandedChunk(selectedChunk)}
                />
              </div>
            </div>
          )}
        </div>
      </div>
      {expandedChunk && (
        <StreamPayloadDialog
          title={`HTTP Payload 详情 #${expandedChunk.packetId}`}
          subtitle={`${expandedChunk.direction === "client" ? "请求" : "响应"} · stream-index ${expandedChunk.streamIndex} · ${estimateTextBytes(expandedChunk.body)} bytes`}
          meta={[
            { label: "协议", value: "HTTP" },
            { label: "Stream", value: httpStream.id },
            { label: "Packet", value: `#${expandedChunk.packetId}` },
            { label: "方向", value: expandedChunk.direction === "client" ? "请求" : "响应" },
            { label: "Stream Index", value: expandedChunk.streamIndex },
            { label: "视图", value: viewMode },
            { label: "原始字节", value: `${estimateTextBytes(expandedChunk.body)} bytes` },
            { label: "预览阈值", value: `${MAX_HTTP_PREVIEW_CHARS} chars` },
          ]}
          extraActions={(
            <button
              type="button"
              onClick={() => navigate("/misc")}
              className="inline-flex items-center gap-1 rounded-md border border-cyan-200 bg-cyan-50 px-2.5 py-1.5 text-xs font-medium text-cyan-700 shadow-sm transition-colors hover:bg-cyan-100"
            >
              打开 MISC 解码工作台
            </button>
          )}
          content={renderHTTPChunk(expandedChunk.body, viewMode, true)}
          highlight={deferredSearch}
          filename={`http-stream-${httpStream.id}-packet-${expandedChunk.packetId}.txt`}
          onClose={() => setExpandedChunk(null)}
        />
      )}
    </div>
  );
}

function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 HTTP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  const overrides = meta.overrideCount && meta.overrideCount > 0 ? ` / overrides ${meta.overrideCount}` : "";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}${overrides}`;
}

function renderHTTPChunk(body: string, viewMode: HTTPViewMode, expanded = false): string {
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

function isHTTPChunkTruncated(body: string, viewMode: HTTPViewMode): boolean {
  return renderHTTPChunk(body, viewMode, true).length > MAX_HTTP_PREVIEW_CHARS;
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

function estimateTextBytes(text: string): number {
  return new TextEncoder().encode(text || "").length;
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
