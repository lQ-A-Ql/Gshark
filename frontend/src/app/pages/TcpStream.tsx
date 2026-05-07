import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, Download } from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { useSentinel } from "../state/SentinelContext";
import { cn } from "../components/ui/utils";
import { StreamChunkCard, StreamControlBar, StreamCurrentChunkPanel, StreamNavigator, StreamPayloadDialog, StreamSearchBar, ViewModeToggle, WorkbenchChip, WorkbenchTitleBar } from "../components/stream/StreamWorkbench";
import { bridge } from "../integrations/wailsBridge";
import type { StreamLoadMeta } from "../core/types";
import { parseChunkBytes, bytesToAscii, bytesToHexDump, estimatePayloadBytes } from "../core/stream-utils";
import { downloadText } from "../utils/browserFile";

type RawViewMode = "ascii" | "hex" | "raw";
type RawChunk = { packetId: number; direction: string; body: string };
type VisibleRawChunk = RawChunk & { key: string; streamIndex: number };

const STREAM_PAGE_SIZE = 96;
const MAX_PREVIEW_BYTES = 4096;

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
  const [selectedChunkIndex, setSelectedChunkIndex] = useState(0);
  const [expandedChunk, setExpandedChunk] = useState<VisibleRawChunk | null>(null);
  const [search, setSearch] = useState("");
  const consumedRouteStreamIdRef = useRef<number | null>(null);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { tcpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();

  useEffect(() => {
    setStreamView({
      id: tcpStream.id,
      protocol: "TCP" as const,
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
    setSearch("");
    setSelectedChunkIndex(0);
    setExpandedChunk(null);
    if (viewportRef.current) {
      viewportRef.current.scrollTop = 0;
    }
  }, [tcpStream.id]);

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const hasPendingRouteStream = routeStreamId >= 0 && routeStreamId !== consumedRouteStreamIdRef.current;
    const streamId = hasPendingRouteStream ? routeStreamId : streamView.id < 0 ? selectedStreamId : -1;
    if (streamId < 0 || !streamIds.tcp.includes(streamId) || streamView.id === streamId) {
      return;
    }
    if (hasPendingRouteStream) {
      consumedRouteStreamIdRef.current = routeStreamId;
    }
    void setActiveStream("TCP", streamId);
  }, [location.state, selectedPacket?.streamId, setActiveStream, streamIds.tcp, streamView.id]);

  const currentIndex = streamIds.tcp.findIndex((id) => id === streamView.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.tcp.length || 1}` : `-- / ${streamIds.tcp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.tcp.length - 1;
  const deferredSearch = useDeferredValue(search);
  const allChunks = useMemo<VisibleRawChunk[]>(
    () => streamView.chunks.map((chunk, index) => ({
      ...chunk,
      key: `${chunk.packetId}-${chunk.direction}-${index}`,
      streamIndex: index,
    })),
    [streamView.chunks],
  );
  const displayChunks = useMemo<VisibleRawChunk[]>(() => {
    const query = deferredSearch.trim().toLowerCase();
    if (!query) return allChunks;
    return allChunks.filter((chunk) => chunk.body.toLowerCase().includes(query));
  }, [allChunks, deferredSearch]);
  const matchCount = useMemo(() => {
    const query = deferredSearch.trim().toLowerCase();
    if (!query) return 0;
    return displayChunks.reduce((sum, chunk) => sum + countOccurrences(chunk.body, query), 0);
  }, [deferredSearch, displayChunks]);
  const selectedChunk = displayChunks[selectedChunkIndex] ?? null;
  const selectedChunkRendered = useMemo(
    () => renderStreamChunk(selectedChunk?.body ?? "", viewMode, false),
    [selectedChunk, viewMode],
  );

  useEffect(() => {
    if (displayChunks.length === 0) {
      setSelectedChunkIndex(0);
      return;
    }
    setSelectedChunkIndex((prev) => Math.min(prev, displayChunks.length - 1));
  }, [displayChunks.length]);

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

  function exportAll() {
    const content = streamView.chunks
      .map((chunk) => `--- ${chunk.direction === "client" ? "CLIENT -> SERVER" : "SERVER -> CLIENT"} [packet:${chunk.packetId}] ---\n${chunk.body}`)
      .join("\n\n");
    downloadText(`tcp-stream-${streamView.id}.txt`, content);
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.22),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <WorkbenchTitleBar
        onBack={() => navigate(-1)}
        title={`TCP 流追踪 (stream eq ${streamView.id})`}
        subtitle={(
          <span className="flex min-w-0 items-center gap-1 font-mono">
            <span className="truncate">{streamView.from}</span>
            <ArrowLeftRight className="h-3 w-3 shrink-0" />
            <span className="truncate">{streamView.to}</span>
          </span>
        )}
        meta={(
          <>
            <WorkbenchChip>
            已载入 {streamView.chunks.length}/{streamView.totalChunks || streamView.chunks.length}
            </WorkbenchChip>
            <WorkbenchChip className="max-w-[520px] truncate">
            {formatLoadMeta(streamView.loadMeta)}
            </WorkbenchChip>
          </>
        )}
      />

      <div className="grid min-h-0 flex-1 gap-4 bg-transparent p-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.95fr)]">
        <div
          ref={viewportRef}
          className="min-h-0 overflow-auto rounded-[24px] border border-white/80 bg-white/88 p-4 font-mono text-sm leading-relaxed shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl"
          onScroll={(event) => {
            const nextScrollTop = event.currentTarget.scrollTop;
            const nearBottom = nextScrollTop + event.currentTarget.clientHeight >= event.currentTarget.scrollHeight - 480;
            if (nearBottom) {
              void loadMore();
            }
          }}
        >
          {loadError && (
            <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
              {loadError}
            </div>
          )}
          {streamView.loadMeta?.loading && streamView.chunks.length === 0 && (
            <div className="mb-3 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs text-blue-700">
              正在解析 tcp.stream eq {streamView.id}，当前只先加载这一条流。
            </div>
          )}
          <div className="flex max-w-4xl flex-col gap-2">
            {displayChunks.map((chunk, index) => (
              <StreamChunkCard
                key={chunk.key}
                directionLabel={chunk.direction === "client" ? "[客户端 -> 服务端]" : "[服务端 -> 客户端]"}
                packetId={chunk.packetId}
                rendered={renderStreamChunk(chunk.body, viewMode, false)}
                highlight={deferredSearch}
                tone={chunk.direction === "client" ? "border-rose-500/30 bg-rose-500/10 text-rose-700" : "border-blue-500/30 bg-blue-500/10 text-blue-700"}
                selected={selectedChunkIndex === index}
                onSelect={() => setSelectedChunkIndex(index)}
                onOpen={() => setExpandedChunk(chunk)}
                truncated={isChunkTruncated(chunk.body, viewMode)}
              />
            ))}
            {(loadingMore || streamView.hasMore) && (
              <div className="flex justify-center pt-2 text-xs text-muted-foreground">
                {loadingMore ? "正在加载更多流片段..." : "继续下滚可加载更多"}
              </div>
            )}
          </div>
        </div>
        <div className="min-h-0 min-w-0 space-y-4 overflow-auto pb-4 pr-1">
          <StreamCurrentChunkPanel
            description="右侧固定查看当前 TCP payload，解码类实验工具已收敛到 MISC 工作台"
            badge={selectedChunk ? (
              <span className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-semibold shadow-sm",
                selectedChunk.direction === "client"
                  ? "border-rose-200 bg-rose-50 text-rose-700"
                  : "border-blue-200 bg-blue-50 text-blue-700",
              )}>
                {selectedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"}
              </span>
            ) : undefined}
            chips={selectedChunk ? [
              `packet #${selectedChunk.packetId}`,
              `${estimatePayloadBytes(selectedChunk.body)} bytes`,
              `chunk #${selectedChunk.streamIndex + 1}`,
            ] : []}
            content={selectedChunk ? selectedChunkRendered || "(empty payload)" : null}
            highlight={deferredSearch}
            emptyText="选择左侧片段后，可在这里固定查看完整上下文。"
            showOpenButton={selectedChunk ? isChunkTruncated(selectedChunk.body, viewMode) : false}
            onOpen={() => selectedChunk && setExpandedChunk(selectedChunk)}
          />
        </div>
      </div>

      <StreamControlBar>
        <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
          切流 last {streamSwitchMetrics.byProtocol.TCP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.TCP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.TCP.p95Ms}ms / fast-path {streamSwitchMetrics.byProtocol.TCP.cacheHitRate}%
        </div>
        <ViewModeToggle<RawViewMode>
          value={viewMode}
          onChange={setViewMode}
          options={[
            { value: "ascii", label: "ASCII" },
            { value: "hex", label: "Hex Dump" },
            { value: "raw", label: "Raw" },
          ]}
        />
        <StreamNavigator
          protocolLabel="TCP"
          ordinalLabel={ordinalLabel}
          streamId={streamView.id}
          streamTotal={streamIds.tcp.length}
          streamInput={streamInput}
          onStreamInputChange={setStreamInput}
          onSubmitStream={() => {
            const id = Number(streamInput);
            if (id >= 0) void setActiveStream("TCP", id);
          }}
          onPrev={() => {
            if (hasPrev) void setActiveStream("TCP", streamIds.tcp[currentIndex - 1]);
          }}
          onNext={() => {
            if (hasNext) void setActiveStream("TCP", streamIds.tcp[currentIndex + 1]);
          }}
          hasPrev={hasPrev}
          hasNext={hasNext}
        />
        <StreamSearchBar
          value={search}
          onChange={(value) => {
            setSearch(value);
            setSelectedChunkIndex(0);
          }}
          onPrev={() => setSelectedChunkIndex((prev) => Math.max(prev - 1, 0))}
          onNext={() => setSelectedChunkIndex((prev) => Math.min(prev + 1, Math.max(0, displayChunks.length - 1)))}
          matchCount={matchCount}
          resultCount={displayChunks.length}
          currentIndex={selectedChunkIndex}
          placeholder="搜索 TCP payload..."
        />
        <WorkbenchChip>
            已载入 {streamView.chunks.length}/{streamView.totalChunks || streamView.chunks.length}
        </WorkbenchChip>
        <div className="ml-auto">
          <button onClick={exportAll} className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent">
            <Download className="h-3.5 w-3.5" /> 导出为文件
          </button>
        </div>
      </StreamControlBar>

      {expandedChunk && (
        <StreamPayloadDialog
          title={`Payload 详情 #${expandedChunk.packetId}`}
          subtitle={`${expandedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"} · chunk #${expandedChunk.streamIndex + 1} · ${estimatePayloadBytes(expandedChunk.body)} bytes`}
          meta={[
            { label: "协议", value: "TCP" },
            { label: "Stream", value: streamView.id },
            { label: "Packet", value: `#${expandedChunk.packetId}` },
            { label: "方向", value: expandedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端" },
            { label: "Chunk", value: `${expandedChunk.streamIndex + 1} / ${streamView.chunks.length}` },
            { label: "视图", value: viewMode },
            { label: "原始估算", value: `${estimatePayloadBytes(expandedChunk.body)} bytes` },
            { label: "预览阈值", value: `${MAX_PREVIEW_BYTES} bytes` },
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
          content={renderStreamChunk(expandedChunk.body, viewMode, true)}
          highlight={deferredSearch}
          filename={`tcp-stream-${streamView.id}-packet-${expandedChunk.packetId}.txt`}
          onClose={() => setExpandedChunk(null)}
        />
      )}
    </div>
  );
}

function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 TCP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  const overrides = meta.overrideCount && meta.overrideCount > 0 ? ` / overrides ${meta.overrideCount}` : "";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}${overrides}`;
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

function countOccurrences(text: string, query: string): number {
  if (!query) return 0;
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

function renderStreamChunk(body: string, mode: RawViewMode, expanded = false): string {
  const raw = body || "";
  if (mode === "raw") {
    if (!raw) return "(empty payload)";
    if (expanded || raw.length <= MAX_PREVIEW_BYTES * 3) {
      return raw;
    }
    return `${raw.slice(0, MAX_PREVIEW_BYTES * 3)}\n\n... 已截断，点击查看完整 payload`;
  }

  const bytes = parseChunkBytes(raw, expanded ? Number.POSITIVE_INFINITY : MAX_PREVIEW_BYTES);
  if (mode === "hex") {
    const rendered = bytesToHexDump(bytes);
    return expanded || !isChunkTruncated(raw, mode)
      ? rendered
      : `${rendered}\n\n... 已截断，点击查看完整 payload`;
  }

  const rendered = bytesToAscii(bytes);
  return expanded || !isChunkTruncated(raw, mode)
    ? rendered
    : `${rendered}\n\n... 已截断，点击查看完整 payload`;
}
