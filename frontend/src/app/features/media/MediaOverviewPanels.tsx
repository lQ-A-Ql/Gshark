import { FileText, Loader2, Square, Video } from "lucide-react";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import type { MediaAnalysis, SpeechBatchTaskStatus } from "../../core/types";

interface MediaBatchActionsProps {
  hasAudioArtifacts: boolean;
  batchStarting: boolean;
  batchStatus: SpeechBatchTaskStatus;
  onStartBatchTranscription: (force?: boolean) => void;
  onCancelBatchTranscription: () => void;
}

export function MediaBatchActions({
  hasAudioArtifacts,
  batchStarting,
  batchStatus,
  onStartBatchTranscription,
  onCancelBatchTranscription,
}: MediaBatchActionsProps) {
  if (!hasAudioArtifacts) {
    return null;
  }

  const batchRunning = Boolean(batchStatus.taskId) && !batchStatus.done;

  return (
    <div className="mb-3 flex flex-wrap items-center gap-2">
      <button
        className="inline-flex items-center gap-1 rounded border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-medium text-rose-700 hover:bg-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
        onClick={() => onStartBatchTranscription(false)}
        disabled={batchStarting || batchRunning}
      >
        {batchStarting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileText className="h-3.5 w-3.5" />}
        批量转写音频
      </button>
      <button
        className="inline-flex items-center gap-1 rounded border border-border bg-card px-3 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
        onClick={() => onStartBatchTranscription(true)}
        disabled={batchStarting || batchRunning}
      >
        强制重新转写
      </button>
      {batchRunning && (
        <button
          className="inline-flex items-center gap-1 rounded border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-100"
          onClick={onCancelBatchTranscription}
        >
          <Square className="h-3.5 w-3.5" />
          取消
        </button>
      )}
    </div>
  );
}

interface MediaLoadingNoticeProps {
  loading: boolean;
}

export function MediaLoadingNotice({ loading }: MediaLoadingNoticeProps) {
  if (!loading) {
    return null;
  }

  return (
    <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
      正在识别 RTP / RTSP / Moonlight / GameStream 并尝试还原媒体流...
    </div>
  );
}

interface MediaOverviewStatsProps {
  analysis: MediaAnalysis;
}

export function MediaOverviewStats({ analysis }: MediaOverviewStatsProps) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
      <StatCard title="相关流量包" value={analysis.totalMediaPackets.toLocaleString()} />
      <StatCard title="协议标签" value={String(analysis.protocols.length)} />
      <StatCard title="会话数" value={analysis.sessions.length.toLocaleString()} />
      <StatCard
        title="已导出媒体流"
        value={analysis.sessions.filter((item) => item.artifact).length.toLocaleString()}
      />
    </div>
  );
}

interface MediaDistributionPanelsProps {
  analysis: MediaAnalysis;
}

export function MediaDistributionPanels({ analysis }: MediaDistributionPanelsProps) {
  return (
    <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel title="协议分布">
        <BucketChart data={analysis.protocols} barClassName="bg-blue-500" maxHeightClassName="max-h-[320px]" />
      </Panel>
      <Panel title="应用分布">
        <BucketChart data={analysis.applications} barClassName="bg-violet-500" maxHeightClassName="max-h-[320px]" />
      </Panel>
    </div>
  );
}

interface MediaNotesPanelProps {
  notes: string[];
}

export function MediaNotesPanel({ notes }: MediaNotesPanelProps) {
  return (
    <Panel title="分析提示" className="mt-4">
      <div className="space-y-2 text-sm">
        {notes.length === 0 ? (
          <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">
            当前抓包未识别到媒体流。
          </div>
        ) : (
          notes.map((note, index) => (
            <div
              key={`${note}-${index}`}
              className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2"
            >
              <Video className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
              <span>{note}</span>
            </div>
          ))
        )}
      </div>
    </Panel>
  );
}
