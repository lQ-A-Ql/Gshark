import { StreamChunkCard, StreamCurrentChunkPanel } from "../components/stream/StreamWorkbench";
import { cn } from "../components/ui/utils";
import { estimateTextBytes, isHTTPChunkTruncated, renderHTTPChunk, type HTTPViewMode } from "./HttpStreamUtils";
import type { HTTPChunk } from "./HttpStreamChunks";

interface HttpStreamPayloadGridProps {
  chunks: HTTPChunk[];
  deferredSearch: string;
  displayCount: number;
  renderLimit: number;
  selectedChunk?: HTTPChunk;
  selectedIndex: number;
  selectedRendered: string;
  viewMode: HTTPViewMode;
  onLoadMore: () => void;
  onOpenChunk: (chunk: HTTPChunk) => void;
  onSelectChunk: (index: number) => void;
}

export function HttpStreamPayloadGrid({
  chunks,
  deferredSearch,
  displayCount,
  renderLimit,
  selectedChunk,
  selectedIndex,
  selectedRendered,
  viewMode,
  onLoadMore,
  onOpenChunk,
  onSelectChunk,
}: HttpStreamPayloadGridProps) {
  if (displayCount === 0) {
    return <div className="gshark-soft-fill px-4 py-3 text-xs text-muted-foreground">当前流没有可展示内容。</div>;
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]">
      <div className="flex min-h-0 flex-col gap-4">
        {chunks.map((chunk, index) => (
          <HttpStreamChunkCard
            key={chunk.key}
            chunk={chunk}
            index={index}
            search={deferredSearch}
            selected={index === selectedIndex}
            viewMode={viewMode}
            onOpen={onOpenChunk}
            onSelect={onSelectChunk}
          />
        ))}
        {renderLimit < displayCount && (
          <button
            className="gshark-control self-start px-2.5 py-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={onLoadMore}
          >
            加载更多 ({renderLimit}/{displayCount})
          </button>
        )}
      </div>
      <div className="space-y-4 xl:sticky xl:top-0">
        <HttpStreamSelectedChunkPanel
          chunk={selectedChunk}
          content={selectedRendered}
          search={deferredSearch}
          viewMode={viewMode}
          onOpen={onOpenChunk}
        />
      </div>
    </div>
  );
}

interface HttpStreamChunkCardProps {
  chunk: HTTPChunk;
  index: number;
  search: string;
  selected: boolean;
  viewMode: HTTPViewMode;
  onOpen: (chunk: HTTPChunk) => void;
  onSelect: (index: number) => void;
}

function HttpStreamChunkCard({ chunk, index, search, selected, viewMode, onOpen, onSelect }: HttpStreamChunkCardProps) {
  return (
    <StreamChunkCard
      directionLabel={chunk.direction === "client" ? "Request ->" : "<- Response"}
      packetId={chunk.packetId}
      rendered={renderHTTPChunk(chunk.body, viewMode, false)}
      highlight={search}
      tone={
        chunk.direction === "client"
          ? "border-rose-500/30 bg-rose-500/10 text-rose-700"
          : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700"
      }
      selected={selected}
      onSelect={() => onSelect(index)}
      onOpen={() => onOpen(chunk)}
      truncated={isHTTPChunkTruncated(chunk.body, viewMode)}
      minHeight="min-h-0"
    />
  );
}

interface HttpStreamSelectedChunkPanelProps {
  chunk?: HTTPChunk;
  content: string;
  search: string;
  viewMode: HTTPViewMode;
  onOpen: (chunk: HTTPChunk) => void;
}

function HttpStreamSelectedChunkPanel({ chunk, content, search, viewMode, onOpen }: HttpStreamSelectedChunkPanelProps) {
  return (
    <StreamCurrentChunkPanel
      description="按当前视图模式同步预览选中的 HTTP 请求/响应"
      badge={chunk ? <HttpDirectionBadge direction={chunk.direction} /> : undefined}
      chips={
        chunk
          ? [`packet #${chunk.packetId}`, `stream-index ${chunk.streamIndex}`, `${estimateTextBytes(chunk.body)} bytes`]
          : []
      }
      content={chunk ? content || "(empty)" : null}
      highlight={search}
      showOpenButton={chunk ? isHTTPChunkTruncated(chunk.body, viewMode) : false}
      onOpen={() => chunk && onOpen(chunk)}
    />
  );
}

function HttpDirectionBadge({ direction }: { direction: HTTPChunk["direction"] }) {
  return (
    <span
      className={cn(
        "gshark-diffuse-chip px-2.5 py-1 text-[11px] font-semibold",
        direction === "client"
          ? "border-rose-200/30 bg-rose-50/20 text-rose-700"
          : "border-emerald-200/30 bg-emerald-50/20 text-emerald-700",
      )}
    >
      {direction === "client" ? "请求" : "响应"}
    </span>
  );
}
