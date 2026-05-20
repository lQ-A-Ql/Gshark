import { type MutableRefObject } from "react";
import { StreamChunkCard, StreamCurrentChunkPanel } from "../components/stream/StreamWorkbench";
import type { StreamLoadMeta } from "../core/types";
import { RawDirectionBadge } from "./RawStreamDirectionBadge";
import { RawStreamLoadMore } from "./RawStreamLoadMore";
import type { RawStreamTone } from "./RawStreamTone";
import {
  buildRawStreamChunkChips,
  getRawDirectionLabel,
  isRawStreamChunkTruncated,
  renderRawStreamChunk,
  type RawViewMode,
  type VisibleRawChunk,
} from "./RawStreamUtils";

interface RawStreamPayloadGridProps {
  chunks: VisibleRawChunk[];
  loadError: string;
  loadingMore: boolean;
  loadingText: string;
  loadMeta?: StreamLoadMeta;
  protocol: "TCP" | "UDP";
  search: string;
  selectedChunkIndex: number;
  streamId: number;
  tone: RawStreamTone;
  viewportRef?: MutableRefObject<HTMLDivElement | null>;
  viewMode: RawViewMode;
  hasMore: boolean;
  totalChunks: number;
  loadedChunkCount: number;
  onLoadMore: () => void;
  onOpenChunk: (chunk: VisibleRawChunk) => void;
  onScrollNearBottom?: () => void;
  onSelectChunk: (index: number) => void;
}

export function RawStreamPayloadGrid({
  chunks,
  loadError,
  loadingMore,
  loadingText,
  loadMeta,
  protocol,
  search,
  selectedChunkIndex,
  streamId,
  tone,
  viewportRef,
  viewMode,
  hasMore,
  totalChunks,
  loadedChunkCount,
  onLoadMore,
  onOpenChunk,
  onScrollNearBottom,
  onSelectChunk,
}: RawStreamPayloadGridProps) {
  return (
    <div
      ref={(node) => {
        if (viewportRef) {
          viewportRef.current = node;
        }
      }}
      className="gshark-aurora-surface min-h-0 overflow-auto p-4 font-mono text-sm leading-relaxed text-slate-800"
      onScroll={(event) => {
        if (!onScrollNearBottom) return;
        const nearBottom =
          event.currentTarget.scrollTop + event.currentTarget.clientHeight >= event.currentTarget.scrollHeight - 480;
        if (nearBottom) onScrollNearBottom();
      }}
    >
      {loadError && (
        <div className="gshark-soft-fill gshark-risk-accent mb-3 px-3 py-2 text-xs text-amber-700">{loadError}</div>
      )}
      {loadMeta?.loading && loadedChunkCount === 0 && (
        <div className="gshark-soft-fill gshark-evidence-accent mb-3 px-3 py-2 text-xs text-blue-700">
          正在解析 {protocol.toLowerCase()}.stream eq {streamId}，当前只先加载这一条流。
        </div>
      )}
      <div className="flex max-w-4xl flex-col gap-2">
        {chunks.map((chunk, index) => (
          <StreamChunkCard
            key={chunk.key}
            directionLabel={`[${getRawDirectionLabel(chunk.direction)}]`}
            packetId={chunk.packetId}
            rendered={renderRawStreamChunk(chunk.body, viewMode, false)}
            highlight={search}
            tone={chunk.direction === "client" ? tone.clientCard : tone.serverCard}
            selected={selectedChunkIndex === index}
            onSelect={() => onSelectChunk(index)}
            onOpen={() => onOpenChunk(chunk)}
            truncated={isRawStreamChunkTruncated(chunk.body, viewMode)}
          />
        ))}
        <RawStreamLoadMore
          hasMore={hasMore}
          loadedChunkCount={loadedChunkCount}
          loadingMore={loadingMore}
          loadingText={loadingText}
          totalChunks={totalChunks}
          onLoadMore={onLoadMore}
        />
      </div>
    </div>
  );
}

interface RawStreamSelectedPanelProps {
  chunk: VisibleRawChunk | null;
  description: string;
  rendered: string;
  search: string;
  tone: RawStreamTone;
  viewMode: RawViewMode;
  onOpenChunk: (chunk: VisibleRawChunk) => void;
}

export function RawStreamSelectedPanel({
  chunk,
  description,
  rendered,
  search,
  tone,
  viewMode,
  onOpenChunk,
}: RawStreamSelectedPanelProps) {
  return (
    <StreamCurrentChunkPanel
      description={description}
      badge={chunk ? <RawDirectionBadge chunk={chunk} tone={tone} /> : undefined}
      chips={chunk ? buildRawStreamChunkChips(chunk) : []}
      content={chunk ? rendered || "(empty payload)" : null}
      highlight={search}
      emptyText="选择左侧片段后，可在这里固定查看完整上下文。"
      showOpenButton={chunk ? isRawStreamChunkTruncated(chunk.body, viewMode) : false}
      onOpen={() => chunk && onOpenChunk(chunk)}
    />
  );
}
