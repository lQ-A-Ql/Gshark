import { ArrowLeftRight, Download } from "lucide-react";
import { type ReactNode } from "react";
import { useNavigate } from "react-router";
import {
  StreamChunkCard,
  StreamCurrentChunkPanel,
  StreamNavigator,
  StreamPayloadDialog,
  StreamSearchBar,
  ViewModeToggle,
  WorkbenchChip,
  WorkbenchTitleBar,
} from "../components/stream/StreamWorkbench";
import { cn } from "../components/ui/utils";
import type { StreamSwitchMetrics } from "../core/types";
import {
  estimateTextBytes,
  formatLoadMeta,
  isHTTPChunkTruncated,
  MAX_HTTP_PREVIEW_CHARS,
  renderHTTPChunk,
  type HTTPViewMode,
} from "./HttpStreamUtils";
import type { HTTPChunk } from "./HttpStreamChunks";

interface HttpStreamTitleBarProps {
  client: string;
  hasNext: boolean;
  hasPrev: boolean;
  ordinalLabel: string;
  server: string;
  streamId: number;
  streamIds: number[];
  streamInput: string;
  streamSwitchMetrics: StreamSwitchMetrics;
  viewMode: HTTPViewMode;
  onBack: () => void;
  onNext: () => void;
  onPrev: () => void;
  onStreamInputChange: (value: string) => void;
  onSubmitStream: () => void;
  onViewModeChange: (mode: HTTPViewMode) => void;
}

export function HttpStreamTitleBar({
  client,
  hasNext,
  hasPrev,
  ordinalLabel,
  server,
  streamId,
  streamIds,
  streamInput,
  streamSwitchMetrics,
  viewMode,
  onBack,
  onNext,
  onPrev,
  onStreamInputChange,
  onSubmitStream,
  onViewModeChange,
}: HttpStreamTitleBarProps) {
  return (
    <WorkbenchTitleBar
      onBack={onBack}
      title={`HTTP 会话追踪 (stream eq ${streamId})`}
      subtitle={<HttpStreamSubtitle client={client} server={server} />}
      meta={<HttpStreamSwitchMetrics metrics={streamSwitchMetrics} />}
      actions={
        <>
          <StreamNavigator
            protocolLabel="HTTP"
            ordinalLabel={ordinalLabel}
            streamId={streamId}
            streamTotal={streamIds.length}
            streamInput={streamInput}
            onStreamInputChange={onStreamInputChange}
            onSubmitStream={onSubmitStream}
            onPrev={onPrev}
            onNext={onNext}
            hasPrev={hasPrev}
            hasNext={hasNext}
          />
          <ViewModeToggle<HTTPViewMode>
            label="视图"
            value={viewMode}
            onChange={onViewModeChange}
            options={[
              { value: "formatted", label: "Formatted" },
              { value: "raw", label: "Raw" },
              { value: "hex", label: "Hex" },
            ]}
            className="py-1"
          />
        </>
      }
    />
  );
}

function HttpStreamSubtitle({ client, server }: { client: string; server: string }) {
  return (
    <span className="flex min-w-0 items-center gap-1 font-mono">
      <span className="truncate">{client}</span>
      <ArrowLeftRight className="h-3 w-3 shrink-0" />
      <span className="truncate">{server}</span>
    </span>
  );
}

function HttpStreamSwitchMetrics({ metrics }: { metrics: StreamSwitchMetrics }) {
  return (
    <WorkbenchChip className="max-w-[300px] truncate">
      切流 last {metrics.byProtocol.HTTP.lastMs}ms / p50 {metrics.byProtocol.HTTP.p50Ms}ms / p95{" "}
      {metrics.byProtocol.HTTP.p95Ms}ms / fast-path {metrics.byProtocol.HTTP.cacheHitRate}%
    </WorkbenchChip>
  );
}

interface HttpStreamToolbarProps {
  currentIndex: number;
  loadMeta: Parameters<typeof formatLoadMeta>[0];
  matchCount: number;
  resultCount: number;
  search: string;
  onExportAll: () => void;
  onNextMatch: () => void;
  onPrevMatch: () => void;
  onSearchChange: (value: string) => void;
}

export function HttpStreamToolbar({
  currentIndex,
  loadMeta,
  matchCount,
  resultCount,
  search,
  onExportAll,
  onNextMatch,
  onPrevMatch,
  onSearchChange,
}: HttpStreamToolbarProps) {
  return (
    <div className="flex shrink-0 items-center justify-between border-b border-border bg-card px-4 py-2 shadow-sm">
      <StreamSearchBar
        value={search}
        onChange={onSearchChange}
        onPrev={onPrevMatch}
        onNext={onNextMatch}
        matchCount={matchCount}
        resultCount={resultCount}
        currentIndex={currentIndex}
      />
      <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
        {formatLoadMeta(loadMeta)}
      </div>
      <button
        onClick={onExportAll}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent"
      >
        <Download className="h-3.5 w-3.5" /> 导出流文本
      </button>
    </div>
  );
}

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
    return (
      <div className="rounded-md border border-border bg-card px-4 py-3 text-xs text-muted-foreground">
        当前流没有可展示内容。
      </div>
    );
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
            className="self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
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
        "rounded-full border px-2.5 py-1 text-[11px] font-semibold shadow-sm",
        direction === "client"
          ? "border-rose-200 bg-rose-50 text-rose-700"
          : "border-emerald-200 bg-emerald-50 text-emerald-700",
      )}
    >
      {direction === "client" ? "请求" : "响应"}
    </span>
  );
}

interface HttpStreamDialogProps {
  chunk: HTTPChunk;
  streamId: number;
  viewMode: HTTPViewMode;
  search: string;
  onClose: () => void;
}

export function HttpStreamDialog({ chunk, streamId, viewMode, search, onClose }: HttpStreamDialogProps) {
  const navigate = useNavigate();
  return (
    <StreamPayloadDialog
      title={`HTTP Payload 详情 #${chunk.packetId}`}
      subtitle={`${chunk.direction === "client" ? "请求" : "响应"} · stream-index ${chunk.streamIndex} · ${estimateTextBytes(chunk.body)} bytes`}
      meta={buildDialogMeta(chunk, streamId, viewMode)}
      extraActions={<OpenMiscButton onClick={() => navigate("/misc")} />}
      content={renderHTTPChunk(chunk.body, viewMode, true)}
      highlight={search}
      filename={`http-stream-${streamId}-packet-${chunk.packetId}.txt`}
      onClose={onClose}
    />
  );
}

function buildDialogMeta(
  chunk: HTTPChunk,
  streamId: number,
  viewMode: HTTPViewMode,
): Array<{ label: string; value: ReactNode }> {
  return [
    { label: "协议", value: "HTTP" },
    { label: "Stream", value: streamId },
    { label: "Packet", value: `#${chunk.packetId}` },
    { label: "方向", value: chunk.direction === "client" ? "请求" : "响应" },
    { label: "Stream Index", value: chunk.streamIndex },
    { label: "视图", value: viewMode },
    { label: "原始字节", value: `${estimateTextBytes(chunk.body)} bytes` },
    { label: "预览阈值", value: `${MAX_HTTP_PREVIEW_CHARS} chars` },
  ];
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
