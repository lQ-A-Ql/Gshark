import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import type { StreamLoadMeta } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";
import { downloadText } from "../utils/browserFile";
import {
  RawStreamControlBar,
  RawStreamDialog,
  RawStreamPayloadGrid,
  RawStreamSelectedPanel,
  RawStreamTitleBar,
  TCP_RAW_STREAM_TONE,
} from "./RawStreamSections";
import {
  buildRawStreamExportContent,
  countRawChunkMatches,
  filterRawChunks,
  renderRawStreamChunk,
  toVisibleRawChunks,
  type RawChunk,
  type RawViewMode,
  type VisibleRawChunk,
} from "./RawStreamUtils";

const STREAM_PAGE_SIZE = 96;

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
      protocol: "TCP",
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
  const ordinalLabel =
    currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.tcp.length || 1}` : `-- / ${streamIds.tcp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.tcp.length - 1;
  const deferredSearch = useDeferredValue(search);
  const allChunks = useMemo<VisibleRawChunk[]>(() => toVisibleRawChunks(streamView.chunks), [streamView.chunks]);
  const displayChunks = useMemo<VisibleRawChunk[]>(
    () => filterRawChunks(allChunks, deferredSearch),
    [allChunks, deferredSearch],
  );
  const matchCount = useMemo(
    () => countRawChunkMatches(displayChunks, deferredSearch),
    [deferredSearch, displayChunks],
  );
  const selectedChunk = displayChunks[selectedChunkIndex] ?? null;
  const selectedChunkRendered = useMemo(
    () => renderRawStreamChunk(selectedChunk?.body ?? "", viewMode, false),
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
      const page = await bridge.getRawStreamPage(
        "TCP",
        streamView.id,
        streamView.nextCursor ?? streamView.chunks.length,
        STREAM_PAGE_SIZE,
      );
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
    downloadText(`tcp-stream-${streamView.id}.txt`, buildRawStreamExportContent(streamView.chunks));
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.22),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <RawStreamTitleBar
        chunkCount={streamView.chunks.length}
        from={streamView.from}
        loadMeta={streamView.loadMeta}
        protocol="TCP"
        streamId={streamView.id}
        to={streamView.to}
        totalChunks={streamView.totalChunks}
        onBack={() => navigate(-1)}
      />

      <div className="grid min-h-0 flex-1 gap-4 bg-transparent p-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.95fr)]">
        <RawStreamPayloadGrid
          chunks={displayChunks}
          hasMore={streamView.hasMore}
          loadedChunkCount={streamView.chunks.length}
          loadError={loadError}
          loadingMore={loadingMore}
          loadingText="继续下滚可加载更多"
          loadMeta={streamView.loadMeta}
          protocol="TCP"
          search={deferredSearch}
          selectedChunkIndex={selectedChunkIndex}
          streamId={streamView.id}
          tone={TCP_RAW_STREAM_TONE}
          totalChunks={streamView.totalChunks}
          viewportRef={viewportRef}
          viewMode={viewMode}
          onLoadMore={() => void loadMore()}
          onOpenChunk={setExpandedChunk}
          onScrollNearBottom={() => void loadMore()}
          onSelectChunk={setSelectedChunkIndex}
        />
        <div className="min-h-0 min-w-0 space-y-4 overflow-auto pb-4 pr-1">
          <RawStreamSelectedPanel
            chunk={selectedChunk}
            description="右侧固定查看当前 TCP payload，解码类实验工具已收敛到 MISC 工作台"
            rendered={selectedChunkRendered}
            search={deferredSearch}
            tone={TCP_RAW_STREAM_TONE}
            viewMode={viewMode}
            onOpenChunk={setExpandedChunk}
          />
        </div>
      </div>

      <RawStreamControlBar
        currentIndex={selectedChunkIndex}
        hasNext={hasNext}
        hasPrev={hasPrev}
        loadedChunkCount={streamView.chunks.length}
        matchCount={matchCount}
        metrics={streamSwitchMetrics}
        ordinalLabel={ordinalLabel}
        protocol="TCP"
        resultCount={displayChunks.length}
        search={search}
        streamId={streamView.id}
        streamInput={streamInput}
        streamTotal={streamIds.tcp.length}
        totalChunks={streamView.totalChunks}
        viewMode={viewMode}
        onExportAll={exportAll}
        onNext={() => {
          if (hasNext) void setActiveStream("TCP", streamIds.tcp[currentIndex + 1]);
        }}
        onNextMatch={() => setSelectedChunkIndex((prev) => Math.min(prev + 1, Math.max(0, displayChunks.length - 1)))}
        onPrev={() => {
          if (hasPrev) void setActiveStream("TCP", streamIds.tcp[currentIndex - 1]);
        }}
        onPrevMatch={() => setSelectedChunkIndex((prev) => Math.max(prev - 1, 0))}
        onSearchChange={(value) => {
          setSearch(value);
          setSelectedChunkIndex(0);
        }}
        onStreamInputChange={setStreamInput}
        onSubmitStream={() => {
          const id = Number(streamInput);
          if (id >= 0) void setActiveStream("TCP", id);
        }}
        onViewModeChange={setViewMode}
      />

      {expandedChunk && (
        <RawStreamDialog
          chunk={expandedChunk}
          protocol="TCP"
          search={deferredSearch}
          streamId={streamView.id}
          totalChunks={streamView.chunks.length}
          viewMode={viewMode}
          onClose={() => setExpandedChunk(null)}
          onOpenMisc={() => navigate("/misc")}
        />
      )}
    </div>
  );
}
