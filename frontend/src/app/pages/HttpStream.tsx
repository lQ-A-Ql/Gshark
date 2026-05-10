import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { useSentinel } from "../state/SentinelContext";
import { downloadText } from "../utils/browserFile";
import {
  buildHTTPChunks,
  countHTTPChunkMatches,
  exportHTTPChunks,
  filterHTTPChunks,
  INITIAL_HTTP_RENDER_LIMIT,
  type HTTPChunk,
} from "./HttpStreamChunks";
import { HttpStreamDialog, HttpStreamPayloadGrid, HttpStreamTitleBar, HttpStreamToolbar } from "./HttpStreamSections";
import { renderHTTPChunk, type HTTPViewMode } from "./HttpStreamUtils";

export default function HttpStream() {
  const navigate = useNavigate();
  const location = useLocation();
  const { httpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();
  const [viewMode, setViewMode] = useState<HTTPViewMode>("formatted");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState(0);
  const [streamInput, setStreamInput] = useState("");
  const [renderLimit, setRenderLimit] = useState(INITIAL_HTTP_RENDER_LIMIT);
  const [expandedChunk, setExpandedChunk] = useState<HTTPChunk | null>(null);
  const consumedRouteStreamIdRef = useRef<number | null>(null);
  const deferredSearch = useDeferredValue(search);
  const currentIndex = streamIds.http.findIndex((id) => id === httpStream.id);
  const ordinalLabel =
    currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.http.length || 1}` : `-- / ${streamIds.http.length || 0}`;
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

  useEffect(() => {
    setRenderLimit(INITIAL_HTTP_RENDER_LIMIT);
    setCursor(0);
    setExpandedChunk(null);
  }, [httpStream.id]);

  useEffect(() => {
    setStreamInput(httpStream.id >= 0 ? String(httpStream.id) : "");
  }, [httpStream.id]);

  const allChunks = useMemo(() => buildHTTPChunks(httpStream), [httpStream]);
  const displayChunks = useMemo(() => filterHTTPChunks(allChunks, deferredSearch), [allChunks, deferredSearch]);
  const matchCount = useMemo(
    () => countHTTPChunkMatches(displayChunks, deferredSearch),
    [deferredSearch, displayChunks],
  );
  const selectedIndex = Math.min(cursor, Math.max(0, displayChunks.length - 1));
  const selectedChunk = displayChunks[selectedIndex];
  const visibleChunks = useMemo(() => displayChunks.slice(0, renderLimit), [displayChunks, renderLimit]);
  const deferredVisibleChunks = useDeferredValue(visibleChunks);
  const deferredSelectedIndex = useDeferredValue(selectedIndex);
  const selectedChunkRendered = useMemo(
    () => (selectedChunk ? renderHTTPChunk(selectedChunk.body, viewMode, false) : ""),
    [selectedChunk, viewMode],
  );

  const submitStream = () => {
    const id = Number(streamInput);
    if (id >= 0) void setActiveStream("HTTP", id);
  };

  const exportAll = () => {
    downloadText(`http-stream-${httpStream.id}.txt`, exportHTTPChunks(allChunks));
  };

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.26),transparent_34%),linear-gradient(180deg,#fbfaff_0%,#f6f7ff_42%,#f8fafc_100%)] text-sm text-foreground">
      <HttpStreamTitleBar
        client={httpStream.client}
        hasNext={hasNext}
        hasPrev={hasPrev}
        ordinalLabel={ordinalLabel}
        server={httpStream.server}
        streamId={httpStream.id}
        streamIds={streamIds.http}
        streamInput={streamInput}
        streamSwitchMetrics={streamSwitchMetrics}
        viewMode={viewMode}
        onBack={() => navigate(-1)}
        onNext={() => {
          if (hasNext) void setActiveStream("HTTP", streamIds.http[currentIndex + 1]);
        }}
        onPrev={() => {
          if (hasPrev) void setActiveStream("HTTP", streamIds.http[currentIndex - 1]);
        }}
        onStreamInputChange={setStreamInput}
        onSubmitStream={submitStream}
        onViewModeChange={setViewMode}
      />

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <HttpStreamToolbar
          currentIndex={selectedIndex}
          loadMeta={httpStream.loadMeta}
          matchCount={matchCount}
          resultCount={displayChunks.length}
          search={search}
          onExportAll={exportAll}
          onNextMatch={() => setCursor((prev) => Math.min(prev + 1, Math.max(0, displayChunks.length - 1)))}
          onPrevMatch={() => setCursor((prev) => Math.max(prev - 1, 0))}
          onSearchChange={(value) => {
            setSearch(value);
            setCursor(0);
          }}
        />

        <div className="flex-1 overflow-auto p-4">
          <HttpStreamPayloadGrid
            chunks={deferredVisibleChunks}
            deferredSearch={deferredSearch}
            displayCount={displayChunks.length}
            renderLimit={renderLimit}
            selectedChunk={selectedChunk}
            selectedIndex={deferredSelectedIndex}
            selectedRendered={selectedChunkRendered}
            viewMode={viewMode}
            onLoadMore={() => setRenderLimit((prev) => Math.min(prev + 180, displayChunks.length))}
            onOpenChunk={setExpandedChunk}
            onSelectChunk={setCursor}
          />
        </div>
      </div>

      {expandedChunk && (
        <HttpStreamDialog
          chunk={expandedChunk}
          streamId={httpStream.id}
          viewMode={viewMode}
          search={deferredSearch}
          onClose={() => setExpandedChunk(null)}
        />
      )}
    </div>
  );
}
