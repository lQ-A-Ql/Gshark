import { memo, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, Download, Minimize2, ChevronLeft, ChevronRight, ArrowLeft, X } from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useSentinel } from "../state/SentinelContext";
import { bridge } from "../integrations/wailsBridge";
import type { StreamLoadMeta } from "../core/types";
import { StreamDecoderWorkbench } from "../components/StreamDecoderWorkbench";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

type RawViewMode = "ascii" | "hex" | "raw";
type RawChunk = { packetId: number; direction: string; body: string };

const STREAM_PAGE_SIZE = 96;
const MAX_PREVIEW_BYTES = 4096;
const ROW_HEIGHT = 172;
const BUFFER = 6;

export default function TcpStream() {
  const [viewMode, setViewMode] = useState<RawViewMode>("ascii");
  const [streamInput, setStreamInput] = useState("");
  const [streamView, setStreamView] = useState(() => ({
    id: -1,
    protocol: "TCP" as const,
    from: "",
    to: "",
    chunks: [] as RawChunk[],
    loadMeta: undefined as StreamLoadMeta | undefined,
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
  }));
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [selectedChunk, setSelectedChunk] = useState<RawChunk | null>(null);
  const [expandedChunk, setExpandedChunk] = useState<RawChunk | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(360);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { tcpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();

  useEffect(() => {
    setStreamView({
      id: tcpStream.id,
      protocol: tcpStream.protocol,
      from: tcpStream.from,
      to: tcpStream.to,
      chunks: tcpStream.chunks,
      loadMeta: tcpStream.loadMeta,
      nextCursor: tcpStream.nextCursor ?? tcpStream.chunks.length,
      totalChunks: tcpStream.totalChunks ?? tcpStream.chunks.length,
      hasMore: tcpStream.hasMore ?? false,
    });
  }, [tcpStream]);

  useEffect(() => {
    setStreamInput(tcpStream.id >= 0 ? String(tcpStream.id) : "");
    setLoadError("");
    setSelectedChunk(null);
    setExpandedChunk(null);
    setScrollTop(0);
    if (viewportRef.current) {
      viewportRef.current.scrollTop = 0;
    }
  }, [tcpStream.id]);

  useEffect(() => {
    if (streamView.chunks.length === 0) {
      setSelectedChunk(null);
      return;
    }
    setSelectedChunk((prev) => {
      if (!prev) {
        return streamView.chunks[0];
      }
      const current = streamView.chunks.find((chunk) => chunk.packetId === prev.packetId && chunk.direction === prev.direction);
      return current ?? streamView.chunks[0];
    });
  }, [streamView.chunks]);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport || typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      setViewportHeight(Math.max(160, Math.floor(entry.contentRect.height)));
    });
    observer.observe(viewport);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const streamId = routeStreamId >= 0 ? routeStreamId : selectedStreamId;
    if (streamId < 0 || !streamIds.tcp.includes(streamId) || streamView.id >= 0) {
      return;
    }
    void setActiveStream("TCP", streamId);
  }, [location.state, selectedPacket?.streamId, setActiveStream, streamIds.tcp, streamView.id]);

  const currentIndex = streamIds.tcp.findIndex((id) => id === streamView.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.tcp.length || 1}` : `-- / ${streamIds.tcp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.tcp.length - 1;

  const totalHeight = Math.max(streamView.chunks.length * ROW_HEIGHT, viewportHeight);
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER);
  const endIndex = Math.min(
    Math.max(streamView.chunks.length - 1, 0),
    Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + BUFFER,
  );
  const visibleChunks = useMemo(
    () => streamView.chunks.slice(startIndex, endIndex + 1),
    [streamView.chunks, startIndex, endIndex],
  );

  async function loadMore() {
    if (loadingMore || !streamView.hasMore) return;
    setLoadingMore(true);
    setLoadError("");
    try {
      const page = await bridge.getRawStreamPage("TCP", streamView.id, streamView.nextCursor ?? streamView.chunks.length, STREAM_PAGE_SIZE);
      setStreamView((prev) => {
        if (prev.id !== page.id) return prev;
        return {
          ...prev,
          from: page.from,
          to: page.to,
          chunks: [...prev.chunks, ...page.chunks],
          loadMeta: page.loadMeta ?? prev.loadMeta,
          nextCursor: page.nextCursor ?? prev.chunks.length + page.chunks.length,
          totalChunks: page.totalChunks ?? prev.totalChunks,
          hasMore: page.hasMore ?? false,
        };
      });
    } catch (error) {
      setLoadError(error instanceof Error && error.message ? error.message : "加载更多流片段失败");
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-background text-sm text-foreground">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-4 py-2">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="rounded p-1 text-foreground transition-colors hover:bg-accent" title="返回上一页">
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div className="h-4 w-px bg-border" />
          <h1 className="flex items-center gap-2 font-semibold text-foreground">
            追踪 TCP 流 (Stream eq {streamView.id})
            <span className="ml-2 flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {streamView.from} <ArrowLeftRight className="h-3 w-3" /> {streamView.to}
            </span>
          </h1>
        </div>
        <button className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"><Minimize2 className="h-4 w-4" /></button>
      </div>

      <div
        ref={viewportRef}
        className="flex-1 overflow-auto bg-card p-4 font-mono text-sm leading-relaxed"
        onScroll={(event) => {
          const nextScrollTop = event.currentTarget.scrollTop;
          setScrollTop(nextScrollTop);
          const nearBottom = nextScrollTop + event.currentTarget.clientHeight >= event.currentTarget.scrollHeight - ROW_HEIGHT * 3;
          if (nearBottom) {
            void loadMore();
          }
        }}
      >
        {loadError && (
          <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
            {loadError}
          </div>
        )}
        {streamView.loadMeta?.loading && streamView.chunks.length === 0 && (
          <div className="mb-3 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs text-blue-700 dark:text-blue-300">
            正在解析 tcp.stream eq {streamView.id}，当前只加载这一条流。
          </div>
        )}
        <div className="relative max-w-4xl" style={{ height: totalHeight }}>
          {visibleChunks.map((chunk, index) => {
            const absoluteIndex = startIndex + index;
            const top = absoluteIndex * ROW_HEIGHT;
            return (
              <div key={chunk.packetId} style={{ position: "absolute", top, left: 0, right: 0, height: ROW_HEIGHT - 8 }}>
                <RawStreamChunkCard
                  chunk={chunk}
                  mode={viewMode}
                  clientTone="border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-400"
                  serverTone="border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400"
                  selected={selectedChunk?.packetId === chunk.packetId && selectedChunk.direction === chunk.direction}
                  onSelect={() => setSelectedChunk(chunk)}
                  onOpen={() => setExpandedChunk(chunk)}
                />
              </div>
            );
          })}
          {(loadingMore || streamView.hasMore) && (
            <div className="absolute left-0 right-0 flex justify-center pt-2 text-xs text-muted-foreground" style={{ top: streamView.chunks.length * ROW_HEIGHT }}>
              {loadingMore ? "正在加载更多流片段..." : "继续下滚可加载更多"}
            </div>
          )}
        </div>
      </div>

      <div className="shrink-0 border-t border-border bg-card/80 px-4 py-4">
        <StreamDecoderWorkbench
          payload={selectedChunk?.body ?? ""}
          chunkLabel={
            selectedChunk
              ? `TCP 片段 #${selectedChunk.packetId} · ${selectedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"}`
              : `TCP 流 stream eq ${streamView.id}`
          }
          tone="blue"
        />
      </div>

      <div className="grid shrink-0 grid-cols-[260px_280px_460px_minmax(140px,1fr)] items-center gap-4 border-t border-border bg-card px-4 py-3 shadow-sm">
        <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
          切流 last {streamSwitchMetrics.byProtocol.TCP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.TCP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.TCP.p95Ms}ms / fast-path {streamSwitchMetrics.byProtocol.TCP.cacheHitRate}%
        </div>
        <div className="flex items-center gap-3 text-xs font-medium text-muted-foreground">
          显示方式:
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "ascii"} onChange={() => setViewMode("ascii")} className="accent-blue-600" /> ASCII
          </label>
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "hex"} onChange={() => setViewMode("hex")} className="accent-blue-600" /> Hex Dump
          </label>
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "raw"} onChange={() => setViewMode("raw")} className="accent-blue-600" /> Raw
          </label>
        </div>
        <div className="grid h-full grid-cols-[auto_28px_minmax(220px,1fr)_28px_72px_120px] items-center gap-2">
          <span className="text-xs text-muted-foreground">流切换:</span>
          <button
            className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
            onClick={() => {
              if (!hasPrev) return;
              void setActiveStream("TCP", streamIds.tcp[currentIndex - 1]);
            }}
            disabled={!hasPrev}
            title={`TCP 流总数: ${streamIds.tcp.length}`}
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="px-2 text-center font-mono text-xs text-foreground" title={`TCP 流总数: ${streamIds.tcp.length}`}>
            第 {ordinalLabel} 条 · stream eq {streamView.id}
          </span>
          <button
            className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
            onClick={() => {
              if (!hasNext) return;
              void setActiveStream("TCP", streamIds.tcp[currentIndex + 1]);
            }}
            disabled={!hasNext}
            title={`TCP 流总数: ${streamIds.tcp.length}`}
          >
            <ChevronRight className="h-4 w-4" />
          </button>
          <input
            value={streamInput}
            onChange={(event) => setStreamInput(event.target.value.replace(/[^0-9]/g, ""))}
            onKeyDown={(event) => {
              if (event.key !== "Enter") return;
              const id = Number(streamInput);
              if (id >= 0) {
                void setActiveStream("TCP", id);
              }
            }}
            className="w-16 rounded border border-border bg-background px-1 py-0.5 text-center text-xs font-mono outline-none"
            placeholder="stream"
            title={`TCP 流总数: ${streamIds.tcp.length}`}
          />
          <span className="text-right text-[11px] text-muted-foreground">
            已载入 {streamView.chunks.length}/{streamView.totalChunks || streamView.chunks.length}
          </span>
        </div>
        <div className="justify-self-end">
          <div className="flex items-center gap-3">
            <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
              {formatLoadMeta(streamView.loadMeta)}
            </div>
            <button className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent">
              <Download className="h-3.5 w-3.5" /> 导出为文件
            </button>
          </div>
        </div>
      </div>

      {expandedChunk && (
        <div className="absolute inset-0 z-20 flex items-center justify-center bg-black/45 px-6 py-8">
          <div className="flex h-full max-h-[80vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div className="text-sm font-semibold text-foreground">
                载荷详情 #{expandedChunk.packetId} · {expandedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"}
              </div>
              <button className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground" onClick={() => setExpandedChunk(null)}>
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4 font-mono text-xs leading-5 text-foreground">
              <pre className="whitespace-pre-wrap break-all">{renderStreamChunk(expandedChunk.body, viewMode, true)}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 TCP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  return `来源 ${source} · cache ${meta.cacheHit ? "yes" : "no"} · index ${meta.indexHit ? "yes" : "no"} · fallback ${meta.fileFallback ? "yes" : "no"} · tshark ${tshark}`;
}

const RawStreamChunkCard = memo(function RawStreamChunkCard({
  chunk,
  mode,
  clientTone,
  serverTone,
  selected,
  onSelect,
  onOpen,
}: {
  chunk: RawChunk;
  mode: RawViewMode;
  clientTone: string;
  serverTone: string;
  selected: boolean;
  onSelect: () => void;
  onOpen: () => void;
}) {
  const rendered = useMemo(() => renderStreamChunk(chunk.body, mode, false), [chunk.body, mode]);
  const tone = chunk.direction === "client" ? clientTone : serverTone;
  const truncated = isChunkTruncated(chunk.body, mode);

  return (
    <div
      className={cn("flex h-full cursor-pointer flex-col rounded-md border px-3 py-2 transition-shadow", tone, selected && "ring-2 ring-blue-300 shadow-sm")}
      onClick={onSelect}
    >
      <span className="mr-2 select-none text-xs font-semibold opacity-60">
        {chunk.direction === "client" ? "[客户端 -> 服务端]" : "[服务端 -> 客户端]"}
      </span>
      <pre className="mt-1 flex-1 overflow-hidden whitespace-pre-wrap break-all text-xs leading-5">{rendered}</pre>
      <div className="mt-2 flex items-center justify-between text-[11px] opacity-80">
        <span>packet #{chunk.packetId}</span>
        {truncated && (
          <button
            className="rounded border border-current/20 px-2 py-1 hover:opacity-100"
            onClick={(event) => {
              event.stopPropagation();
              onOpen();
            }}
          >
            查看完整载荷
          </button>
        )}
      </div>
    </div>
  );
});

function parseChunkBytes(body: string, limit = Number.POSITIVE_INFINITY): number[] {
  const raw = (body ?? "").trim();
  if (!raw) return [];
  const isHex = /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw);
  if (!isHex) {
    return Array.from(new TextEncoder().encode(raw.slice(0, Number.isFinite(limit) ? limit : undefined)));
  }
  const parts = raw.split(":");
  const size = Math.min(parts.length, Number.isFinite(limit) ? limit : parts.length);
  const bytes: number[] = [];
  for (let i = 0; i < size; i += 1) {
    const value = Number.parseInt(parts[i], 16);
    if (Number.isFinite(value)) {
      bytes.push(value);
    }
  }
  return bytes;
}

function bytesToAscii(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  return bytes.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
}

function bytesToHexDump(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  return lines.join("\n");
}

function isHexPayload(body: string): boolean {
  return /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test((body ?? "").trim());
}

function isChunkTruncated(body: string, mode: RawViewMode): boolean {
  const raw = (body ?? "").trim();
  if (!raw) return false;
  if (mode === "raw") {
    return raw.length > MAX_PREVIEW_BYTES * 3;
  }
  if (isHexPayload(raw)) {
    return raw.split(":").length > MAX_PREVIEW_BYTES;
  }
  return raw.length > MAX_PREVIEW_BYTES;
}

function renderStreamChunk(body: string, mode: RawViewMode, expanded = false): string {
  const raw = body || "";
  if (mode === "raw") {
    if (!raw) return "(empty payload)";
    if (expanded || raw.length <= MAX_PREVIEW_BYTES * 3) {
      return raw;
    }
    return `${raw.slice(0, MAX_PREVIEW_BYTES * 3)}\n\n... 已截断，点击查看完整载荷`;
  }

  const bytes = parseChunkBytes(raw, expanded ? Number.POSITIVE_INFINITY : MAX_PREVIEW_BYTES);
  if (mode === "hex") {
    const rendered = bytesToHexDump(bytes);
    return expanded || !isChunkTruncated(raw, mode)
      ? rendered
      : `${rendered}\n\n... 已截断，点击查看完整载荷`;
  }

  const rendered = bytesToAscii(bytes);
  return expanded || !isChunkTruncated(raw, mode)
    ? rendered
    : `${rendered}\n\n... 已截断，点击查看完整载荷`;
}
