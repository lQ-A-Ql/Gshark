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
  UDP_RAW_STREAM_TONE,
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

export default function UdpStream() {
  const [viewMode, setViewMode] = useState<RawViewMode>("ascii");
  const [streamInput, setStreamInput] = useState("");
  const [loadError, setLoadError] = useState("");
  const [selectedChunkIndex, setSelectedChunkIndex] = useState(0);
  const [expandedChunk, setExpandedChunk] = useState<VisibleRawChunk | null>(null);
  const [search, setSearch] = useState("");
  const [streamView, setStreamView] = useState(() => ({
    id: -1,
    protocol: "UDP" as const,
    from: "",
    to: "",
    chunks: [] as RawChunk[],
    loadMeta: undefined as StreamLoadMeta | undefined,
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
  }));
  const [loadingMore, setLoadingMore] = useState(false);
  const consumedRouteStreamIdRef = useRef<number | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { udpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();
  const currentIndex = streamIds.udp.findIndex((id) => id === streamView.id);
  const ordinalLabel =
    currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.udp.length || 1}` : `-- / ${streamIds.udp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.udp.length - 1;
  const deferredSearch = useDeferredValue(search);
  const allChunks = useMemo<VisibleRawChunk[]>(() => toVisibleRawChunks(streamView.chunks), [streamView.chunks]);
  const visibleChunks = useMemo<VisibleRawChunk[]>(
    () => filterRawChunks(allChunks, deferredSearch),
    [allChunks, deferredSearch],
  );
  const matchCount = useMemo(
    () => countRawChunkMatches(visibleChunks, deferredSearch),
    [deferredSearch, visibleChunks],
  );
  const selectedChunk = visibleChunks[selectedChunkIndex] ?? null;
  const selectedChunkRendered = useMemo(
    () => renderRawStreamChunk(selectedChunk?.body ?? "", viewMode, false),
    [selectedChunk, viewMode],
  );

  useEffect(() => {
    setStreamView({
      id: udpStream.id,
      protocol: "UDP",
      from: udpStream.from,
      to: udpStream.to,
      chunks: udpStream.chunks,
      loadMeta: udpStream.loadMeta,
      nextCursor: udpStream.nextCursor ?? udpStream.chunks.length,
      totalChunks: udpStream.totalChunks ?? udpStream.chunks.length,
      hasMore: udpStream.hasMore ?? false,
    });
  }, [udpStream]);

  useEffect(() => {
    setStreamInput(udpStream.id >= 0 ? String(udpStream.id) : "");
    setLoadError("");
    setSearch("");
    setSelectedChunkIndex(0);
    setExpandedChunk(null);
  }, [udpStream.id]);

  useEffect(() => {
    if (visibleChunks.length === 0) {
      setSelectedChunkIndex(0);
      return;
    }
    setSelectedChunkIndex((prev) => Math.min(prev, visibleChunks.length - 1));
  }, [visibleChunks.length]);

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const hasPendingRouteStream = routeStreamId >= 0 && routeStreamId !== consumedRouteStreamIdRef.current;
    const streamId = hasPendingRouteStream ? routeStreamId : streamView.id < 0 ? selectedStreamId : -1;
    if (streamId < 0 || !streamIds.udp.includes(streamId) || streamView.id === streamId) {
      return;
    }
    if (hasPendingRouteStream) {
      consumedRouteStreamIdRef.current = routeStreamId;
    }
    void setActiveStream("UDP", streamId);
  }, [location.state, selectedPacket?.streamId, setActiveStream, streamIds.udp, streamView.id]);

  async function loadMore() {
    if (loadingMore || !streamView.hasMore) return;
    setLoadingMore(true);
    setLoadError("");
    try {
      const page = await bridge.getRawStreamPage(
        "UDP",
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
    downloadText(`udp-stream-${streamView.id}.txt`, buildRawStreamExportContent(streamView.chunks));
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.22),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <RawStreamTitleBar
        chunkCount={streamView.chunks.length}
        from={streamView.from}
        loadMeta={streamView.loadMeta}
        protocol="UDP"
        streamId={streamView.id}
        to={streamView.to}
        totalChunks={streamView.totalChunks}
        onBack={() => navigate(-1)}
      />

      <div className="grid min-h-0 flex-1 gap-4 bg-transparent p-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.95fr)]">
        <RawStreamPayloadGrid
          chunks={visibleChunks}
          hasMore={streamView.hasMore}
          loadedChunkCount={streamView.chunks.length}
          loadError={loadError}
          loadingMore={loadingMore}
          loadingText=""
          loadMeta={streamView.loadMeta}
          protocol="UDP"
          search={deferredSearch}
          selectedChunkIndex={selectedChunkIndex}
          streamId={streamView.id}
          tone={UDP_RAW_STREAM_TONE}
          totalChunks={streamView.totalChunks}
          viewMode={viewMode}
          onLoadMore={() => void loadMore()}
          onOpenChunk={setExpandedChunk}
          onSelectChunk={setSelectedChunkIndex}
        />
        <div className="space-y-4 xl:sticky xl:top-0">
          <RawStreamSelectedPanel
            chunk={selectedChunk}
            description="固定查看当前 UDP payload，解码类实验工具已收敛到 MISC 工作台"
            rendered={selectedChunkRendered}
            search={deferredSearch}
            tone={UDP_RAW_STREAM_TONE}
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
        protocol="UDP"
        resultCount={visibleChunks.length}
        search={search}
        streamId={streamView.id}
        streamInput={streamInput}
        streamTotal={streamIds.udp.length}
        totalChunks={streamView.totalChunks}
        viewMode={viewMode}
        onExportAll={exportAll}
        onNext={() => {
          if (hasNext) void setActiveStream("UDP", streamIds.udp[currentIndex + 1]);
        }}
        onNextMatch={() => setSelectedChunkIndex((prev) => Math.min(prev + 1, Math.max(0, visibleChunks.length - 1)))}
        onPrev={() => {
          if (hasPrev) void setActiveStream("UDP", streamIds.udp[currentIndex - 1]);
        }}
        onPrevMatch={() => setSelectedChunkIndex((prev) => Math.max(prev - 1, 0))}
        onSearchChange={(value) => {
          setSearch(value);
          setSelectedChunkIndex(0);
        }}
        onStreamInputChange={setStreamInput}
        onSubmitStream={() => {
          const id = Number(streamInput);
          if (id >= 0) void setActiveStream("UDP", id);
        }}
        onViewModeChange={setViewMode}
      />

      {expandedChunk && (
        <RawStreamDialog
          chunk={expandedChunk}
          protocol="UDP"
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
