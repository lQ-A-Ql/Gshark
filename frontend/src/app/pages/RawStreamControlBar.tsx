import { Download } from "lucide-react";
import {
  StreamControlBar,
  StreamNavigator,
  StreamSearchBar,
  ViewModeToggle,
  WorkbenchChip,
} from "../components/stream/StreamWorkbench";
import type { StreamProtocol, StreamSwitchMetrics } from "../core/types";
import type { RawViewMode } from "./RawStreamUtils";

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
      <WorkbenchChip>
        切流 last {protocolMetrics.lastMs}ms / p50 {protocolMetrics.p50Ms}ms / p95 {protocolMetrics.p95Ms}ms / fast-path{" "}
        {protocolMetrics.cacheHitRate}%
      </WorkbenchChip>
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
          className="gshark-control gshark-evidence-accent flex items-center gap-1 px-3 py-1.5 text-xs text-foreground transition-all hover:text-accent-foreground"
        >
          <Download className="h-3.5 w-3.5" /> 导出为文件
        </button>
      </div>
    </StreamControlBar>
  );
}
