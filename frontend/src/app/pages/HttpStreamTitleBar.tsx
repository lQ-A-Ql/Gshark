import { ArrowLeftRight, Download } from "lucide-react";
import {
  StreamNavigator,
  StreamSearchBar,
  ViewModeToggle,
  WorkbenchChip,
  WorkbenchTitleBar,
} from "../components/stream/StreamWorkbench";
import type { StreamSwitchMetrics } from "../core/types";
import { formatLoadMeta, type HTTPViewMode } from "./HttpStreamUtils";

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
    <div className="gshark-tile-toolbar gshark-workbench-panel flex shrink-0 items-center justify-between gap-3 border-x-0 border-t-0 px-4 py-2">
      <StreamSearchBar
        value={search}
        onChange={onSearchChange}
        onPrev={onPrevMatch}
        onNext={onNextMatch}
        matchCount={matchCount}
        resultCount={resultCount}
        currentIndex={currentIndex}
      />
      <WorkbenchChip>{formatLoadMeta(loadMeta)}</WorkbenchChip>
      <button
        onClick={onExportAll}
        className="gshark-control flex items-center gap-1 px-3 py-1.5 text-xs text-foreground transition-all hover:text-accent-foreground"
      >
        <Download className="h-3.5 w-3.5" /> 导出流文本
      </button>
    </div>
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
