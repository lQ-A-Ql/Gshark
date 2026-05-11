import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
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
  UDP_RAW_STREAM_TONE,
} from "./RawStreamSections";
import {
  buildRawStreamExportContent,
  countRawChunkMatches,
  filterRawChunks,
  renderRawStreamChunk,
  toVisibleRawChunks,
  type RawViewMode,
  type VisibleRawChunk,
} from "./RawStreamUtils";
import { createEmptyRawStreamView, type RawStreamViewState } from "./RawStreamViewState";
import { useRawStreamRouteSelection, type RawStreamProtocol } from "./useRawStreamRouteSelection";

const STREAM_PAGE_SIZE = 96;

export function RawStreamPage({ protocol }: { protocol: RawStreamProtocol }) {
  const [viewMode, setViewMode] = useState<RawViewMode>("ascii");
  const [streamInput, setStreamInput] = useState("");
  const [loadError, setLoadError] = useState("");
  const [selectedChunkIndex, setSelectedChunkIndex] = useState(0);
  const [expandedChunk, setExpandedChunk] = useState<VisibleRawChunk | null>(null);
  const [search, setSearch] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const [streamView, setStreamView] = useState<RawStreamViewState>(() => createEmptyRawStreamView(protocol));
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { tcpStream, udpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();
  const sourceStream = protocol === "TCP" ? tcpStream : udpStream;
  const streamList = protocol === "TCP" ? streamIds.tcp : streamIds.udp;
  const tone = protocol === "TCP" ? TCP_RAW_STREAM_TONE : UDP_RAW_STREAM_TONE;
  const enableScrollLoad = protocol === "TCP";
  const selectedPanelClass =
    protocol === "TCP" ? "min-h-0 min-w-0 space-y-4 overflow-auto pb-4 pr-1" : "space-y-4 xl:sticky xl:top-0";
  const loadingText = protocol === "TCP" ? "继续下滚可加载更多" : "";

  useEffect(() => {
    setStreamView({
      id: sourceStream.id,
      protocol,
      from: sourceStream.from,
      to: sourceStream.to,
      chunks: sourceStream.chunks,
      loadMeta: sourceStream.loadMeta,
      nextCursor: sourceStream.nextCursor ?? sourceStream.chunks.length,
      totalChunks: sourceStream.totalChunks ?? sourceStream.chunks.length,
      hasMore: sourceStream.hasMore ?? false,
    });
  }, [protocol, sourceStream]);

  useEffect(() => {
    setStreamInput(sourceStream.id >= 0 ? String(sourceStream.id) : "");
    setLoadError("");
    setSearch("");
    setSelectedChunkIndex(0);
    setExpandedChunk(null);
    if (enableScrollLoad && viewportRef.current) {
      viewportRef.current.scrollTop = 0;
    }
  }, [enableScrollLoad, sourceStream.id]);

  useRawStreamRouteSelection({
    locationState: location.state,
    protocol,
    selectedPacketStreamId: selectedPacket?.streamId,
    setActiveStream,
    streamList,
    streamViewId: streamView.id,
  });

  const currentIndex = streamList.findIndex((id) => id === streamView.id);
  const ordinalLabel =
    currentIndex >= 0 ? `${currentIndex + 1} / ${streamList.length || 1}` : `-- / ${streamList.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamList.length - 1;
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
    if (visibleChunks.length === 0) {
      setSelectedChunkIndex(0);
      return;
    }
    setSelectedChunkIndex((prev) => Math.min(prev, visibleChunks.length - 1));
  }, [visibleChunks.length]);

  async function loadMore() {
    if (loadingMore || !streamView.hasMore) return;
    setLoadingMore(true);
    setLoadError("");
    try {
      const page = await bridge.getRawStreamPage(
        protocol,
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
    downloadText(`${protocol.toLowerCase()}-stream-${streamView.id}.txt`, buildRawStreamExportContent(streamView.chunks));
  }

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.22),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <RawStreamTitleBar
        chunkCount={streamView.chunks.length}
        from={streamView.from}
        loadMeta={streamView.loadMeta}
        protocol={protocol}
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
          loadingText={loadingText}
          loadMeta={streamView.loadMeta}
          protocol={protocol}
          search={deferredSearch}
          selectedChunkIndex={selectedChunkIndex}
          streamId={streamView.id}
          tone={tone}
          totalChunks={streamView.totalChunks}
          viewportRef={enableScrollLoad ? viewportRef : undefined}
          viewMode={viewMode}
          onLoadMore={() => void loadMore()}
          onOpenChunk={setExpandedChunk}
          onScrollNearBottom={enableScrollLoad ? () => void loadMore() : undefined}
          onSelectChunk={setSelectedChunkIndex}
        />
        <div className={selectedPanelClass}>
          <RawStreamSelectedPanel
            chunk={selectedChunk}
            description={`固定查看当前 ${protocol} payload，解码类实验工具已收敛到 MISC 工作台`}
            rendered={selectedChunkRendered}
            search={deferredSearch}
            tone={tone}
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
        protocol={protocol}
        resultCount={visibleChunks.length}
        search={search}
        streamId={streamView.id}
        streamInput={streamInput}
        streamTotal={streamList.length}
        totalChunks={streamView.totalChunks}
        viewMode={viewMode}
        onExportAll={exportAll}
        onNext={() => {
          if (hasNext) void setActiveStream(protocol, streamList[currentIndex + 1]);
        }}
        onNextMatch={() => setSelectedChunkIndex((prev) => Math.min(prev + 1, Math.max(0, visibleChunks.length - 1)))}
        onPrev={() => {
          if (hasPrev) void setActiveStream(protocol, streamList[currentIndex - 1]);
        }}
        onPrevMatch={() => setSelectedChunkIndex((prev) => Math.max(prev - 1, 0))}
        onSearchChange={(value) => {
          setSearch(value);
          setSelectedChunkIndex(0);
        }}
        onStreamInputChange={setStreamInput}
        onSubmitStream={() => {
          const id = Number(streamInput);
          if (id >= 0) void setActiveStream(protocol, id);
        }}
        onViewModeChange={setViewMode}
      />

      {expandedChunk && (
        <RawStreamDialog
          chunk={expandedChunk}
          protocol={protocol}
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
