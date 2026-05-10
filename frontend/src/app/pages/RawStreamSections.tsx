import { ArrowLeftRight, Download } from "lucide-react";
import { type MutableRefObject } from "react";
import {
  StreamChunkCard,
  StreamControlBar,
  StreamCurrentChunkPanel,
  StreamNavigator,
  StreamPayloadDialog,
  StreamSearchBar,
  ViewModeToggle,
  WorkbenchChip,
  WorkbenchTitleBar,
} from "../components/stream/StreamWorkbench";
import { cn } from "../components/ui/utils";
import type { StreamLoadMeta, StreamSwitchMetrics, StreamProtocol } from "../core/types";
import {
  buildRawStreamChunkChips,
  buildRawStreamDialogMeta,
  formatRawStreamLoadMeta,
  getRawDirectionLabel,
  isRawStreamChunkTruncated,
  renderRawStreamChunk,
  type RawViewMode,
  type VisibleRawChunk,
} from "./RawStreamUtils";

interface RawStreamTitleBarProps {
  chunkCount: number;
  from: string;
  loadMeta?: StreamLoadMeta;
  protocol: "TCP" | "UDP";
  streamId: number;
  to: string;
  totalChunks: number;
  onBack: () => void;
}

export function RawStreamTitleBar({
  chunkCount,
  from,
  loadMeta,
  protocol,
  streamId,
  to,
  totalChunks,
  onBack,
}: RawStreamTitleBarProps) {
  return (
    <WorkbenchTitleBar
      onBack={onBack}
      title={`${protocol} 流追踪 (stream eq ${streamId})`}
      subtitle={
        <span className="flex min-w-0 items-center gap-1 font-mono">
          <span className="truncate">{from}</span>
          <ArrowLeftRight className="h-3 w-3 shrink-0" />
          <span className="truncate">{to}</span>
        </span>
      }
      meta={
        <>
          <WorkbenchChip>
            已载入 {chunkCount}/{totalChunks || chunkCount}
          </WorkbenchChip>
          <WorkbenchChip className="max-w-[520px] truncate">
            {formatRawStreamLoadMeta(protocol, loadMeta)}
          </WorkbenchChip>
        </>
      }
    />
  );
}

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

export type RawStreamTone = {
  clientBadge: string;
  clientCard: string;
  serverBadge: string;
  serverCard: string;
};

export const TCP_RAW_STREAM_TONE: RawStreamTone = {
  clientBadge: "border-rose-200 bg-rose-50 text-rose-700",
  clientCard: "border-rose-500/30 bg-rose-500/10 text-rose-700",
  serverBadge: "border-blue-200 bg-blue-50 text-blue-700",
  serverCard: "border-blue-500/30 bg-blue-500/10 text-blue-700",
};

export const UDP_RAW_STREAM_TONE: RawStreamTone = {
  clientBadge: "border-amber-200 bg-amber-50 text-amber-700",
  clientCard: "border-amber-500/30 bg-amber-500/10 text-amber-700",
  serverBadge: "border-cyan-200 bg-cyan-50 text-cyan-700",
  serverCard: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700",
};

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
      className="min-h-0 overflow-auto rounded-[24px] border border-white/80 bg-white/88 p-4 font-mono text-sm leading-relaxed shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl"
      onScroll={(event) => {
        if (!onScrollNearBottom) return;
        const nearBottom =
          event.currentTarget.scrollTop + event.currentTarget.clientHeight >= event.currentTarget.scrollHeight - 480;
        if (nearBottom) onScrollNearBottom();
      }}
    >
      {loadError && (
        <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
          {loadError}
        </div>
      )}
      {loadMeta?.loading && loadedChunkCount === 0 && (
        <div className="mb-3 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs text-blue-700">
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

interface RawStreamLoadMoreProps {
  hasMore: boolean;
  loadedChunkCount: number;
  loadingMore: boolean;
  loadingText: string;
  totalChunks: number;
  onLoadMore: () => void;
}

function RawStreamLoadMore({
  hasMore,
  loadedChunkCount,
  loadingMore,
  loadingText,
  totalChunks,
  onLoadMore,
}: RawStreamLoadMoreProps) {
  if (!loadingMore && !hasMore) return null;

  if (loadingText) {
    return (
      <div className="flex justify-center pt-2 text-xs text-muted-foreground">
        {loadingMore ? "正在加载更多流片段..." : loadingText}
      </div>
    );
  }

  return (
    <button
      className="mt-2 self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-60"
      onClick={onLoadMore}
      disabled={loadingMore}
    >
      {loadingMore ? "正在加载..." : `加载更多 (${loadedChunkCount}/${totalChunks || loadedChunkCount})`}
    </button>
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

function RawDirectionBadge({ chunk, tone }: { chunk: VisibleRawChunk; tone: RawStreamTone }) {
  return (
    <span
      className={cn(
        "rounded-full border px-2.5 py-1 text-[11px] font-semibold shadow-sm",
        chunk.direction === "client" ? tone.clientBadge : tone.serverBadge,
      )}
    >
      {getRawDirectionLabel(chunk.direction)}
    </span>
  );
}

interface RawStreamControlBarProps {
  currentIndex: number;
  hasNext: boolean;
  hasPrev: boolean;
  loadedChunkCount: number;
  matchCount: number;
  metrics: StreamSwitchMetrics;
  ordinalLabel: string;
  protocol: StreamProtocol;
  resultCount: number;
  search: string;
  streamId: number;
  streamInput: string;
  streamTotal: number;
  totalChunks: number;
  viewMode: RawViewMode;
  onExportAll: () => void;
  onNext: () => void;
  onNextMatch: () => void;
  onPrev: () => void;
  onPrevMatch: () => void;
  onSearchChange: (value: string) => void;
  onStreamInputChange: (value: string) => void;
  onSubmitStream: () => void;
  onViewModeChange: (mode: RawViewMode) => void;
}

export function RawStreamControlBar({
  currentIndex,
  hasNext,
  hasPrev,
  loadedChunkCount,
  matchCount,
  metrics,
  ordinalLabel,
  protocol,
  resultCount,
  search,
  streamId,
  streamInput,
  streamTotal,
  totalChunks,
  viewMode,
  onExportAll,
  onNext,
  onNextMatch,
  onPrev,
  onPrevMatch,
  onSearchChange,
  onStreamInputChange,
  onSubmitStream,
  onViewModeChange,
}: RawStreamControlBarProps) {
  const protocolMetrics = metrics.byProtocol[protocol];
  return (
    <StreamControlBar>
      <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
        切流 last {protocolMetrics.lastMs}ms / p50 {protocolMetrics.p50Ms}ms / p95 {protocolMetrics.p95Ms}ms / fast-path{" "}
        {protocolMetrics.cacheHitRate}%
      </div>
      <ViewModeToggle<RawViewMode>
        value={viewMode}
        onChange={onViewModeChange}
        options={[
          { value: "ascii", label: "ASCII" },
          { value: "hex", label: "Hex Dump" },
          { value: "raw", label: "Raw" },
        ]}
      />
      <StreamNavigator
        protocolLabel={protocol}
        ordinalLabel={ordinalLabel}
        streamId={streamId}
        streamTotal={streamTotal}
        streamInput={streamInput}
        onStreamInputChange={onStreamInputChange}
        onSubmitStream={onSubmitStream}
        onPrev={onPrev}
        onNext={onNext}
        hasPrev={hasPrev}
        hasNext={hasNext}
      />
      <StreamSearchBar
        value={search}
        onChange={onSearchChange}
        onPrev={onPrevMatch}
        onNext={onNextMatch}
        matchCount={matchCount}
        resultCount={resultCount}
        currentIndex={currentIndex}
        placeholder={`搜索 ${protocol} payload...`}
      />
      <WorkbenchChip>
        已载入 {loadedChunkCount}/{totalChunks || loadedChunkCount}
      </WorkbenchChip>
      <div className="ml-auto">
        <button
          onClick={onExportAll}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent"
        >
          <Download className="h-3.5 w-3.5" /> 导出为文件
        </button>
      </div>
    </StreamControlBar>
  );
}

interface RawStreamDialogProps {
  chunk: VisibleRawChunk;
  protocol: "TCP" | "UDP";
  search: string;
  streamId: number;
  totalChunks: number;
  viewMode: RawViewMode;
  onClose: () => void;
  onOpenMisc: () => void;
}

export function RawStreamDialog({
  chunk,
  protocol,
  search,
  streamId,
  totalChunks,
  viewMode,
  onClose,
  onOpenMisc,
}: RawStreamDialogProps) {
  return (
    <StreamPayloadDialog
      title={`Payload 详情 #${chunk.packetId}`}
      subtitle={`${getRawDirectionLabel(chunk.direction)} · chunk #${chunk.streamIndex + 1} · ${buildRawStreamChunkChips(chunk)[1]}`}
      meta={buildRawStreamDialogMeta(protocol, streamId, chunk, totalChunks, viewMode)}
      extraActions={<OpenMiscButton onClick={onOpenMisc} />}
      content={renderRawStreamChunk(chunk.body, viewMode, true)}
      highlight={search}
      filename={`${protocol.toLowerCase()}-stream-${streamId}-packet-${chunk.packetId}.txt`}
      onClose={onClose}
    />
  );
}

function OpenMiscButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1 rounded-md border border-cyan-200 bg-cyan-50 px-2.5 py-1.5 text-xs font-medium text-cyan-700 shadow-sm transition-colors hover:bg-cyan-100"
    >
      打开 MISC 解码工作台
    </button>
  );
}
