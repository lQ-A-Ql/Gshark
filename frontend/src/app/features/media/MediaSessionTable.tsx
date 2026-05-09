import { Clapperboard, Headphones, Video } from "lucide-react";
import { useMemo, useState } from "react";
import { AnalysisDataTable as DataTable, AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { ExportActionsCell, MediaTypeBadge, TranscriptionCell } from "./MediaSessionCells";

type MediaTab = "all" | "video" | "audio";

interface MediaSessionTableProps {
  sessions: MediaSession[];
  batchStatus: SpeechBatchTaskStatus;
  transcriptions: Record<string, MediaTranscription>;
  transcriptionLoadingToken: string;
  transcriptionStartedAt: number | null;
  batchTokenStartedAt: number | null;
  progressClock: number;
  playbackLoadingToken: string;
  onCopyText: (text: string) => void | Promise<void>;
  onDownloadArtifact: (session: MediaSession) => void | Promise<void>;
  onOpenPlayback: (session: MediaSession) => void | Promise<void>;
  onRunTranscription: (session: MediaSession, force?: boolean) => void | Promise<void>;
}

export function MediaSessionTable({
  sessions,
  batchStatus,
  transcriptions,
  transcriptionLoadingToken,
  transcriptionStartedAt,
  batchTokenStartedAt,
  progressClock,
  playbackLoadingToken,
  onCopyText,
  onDownloadArtifact,
  onOpenPlayback,
  onRunTranscription,
}: MediaSessionTableProps) {
  const [activeTab, setActiveTab] = useState<MediaTab>("all");
  const filteredSessions = useMemo(() => {
    if (activeTab === "all") return sessions;
    return sessions.filter((session) => (session.mediaType || "video") === activeTab);
  }, [activeTab, sessions]);
  const videoCount = useMemo(
    () => sessions.filter((session) => (session.mediaType || "video") === "video").length,
    [sessions],
  );
  const audioCount = useMemo(() => sessions.filter((session) => session.mediaType === "audio").length, [sessions]);

  return (
    <Panel title={`媒体会话 (${sessions.length})`} className="mt-4">
      <div className="mb-3 flex items-center gap-1 border-b border-border pb-2">
        {[
          {
            key: "all" as MediaTab,
            label: "全部",
            count: sessions.length,
            icon: <Clapperboard className="h-3.5 w-3.5" />,
          },
          { key: "video" as MediaTab, label: "视频", count: videoCount, icon: <Video className="h-3.5 w-3.5" /> },
          {
            key: "audio" as MediaTab,
            label: "音频",
            count: audioCount,
            icon: <Headphones className="h-3.5 w-3.5" />,
          },
        ].map((tab) => (
          <button
            key={tab.key}
            className={`inline-flex items-center gap-1 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
              activeTab === tab.key
                ? "bg-blue-600 text-white"
                : "bg-accent text-muted-foreground hover:bg-accent/80 hover:text-foreground"
            }`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.icon}
            {tab.label}
            <span className="ml-0.5 opacity-70">({tab.count})</span>
          </button>
        ))}
      </div>
      <DataTable
        data={filteredSessions}
        rowKey={(session) => session.id}
        maxHeightClassName="max-h-[560px]"
        tableClassName="min-w-[1380px]"
        emptyText="暂无可还原的媒体会话"
        columns={[
          {
            key: "type",
            header: "类型",
            widthClassName: "w-[90px]",
            render: (session) => <MediaTypeBadge session={session} />,
          },
          {
            key: "family",
            header: "族类",
            widthClassName: "w-[140px]",
            render: (session) => (
              <>
                <div className="font-medium">{session.family || "--"}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">{session.tags.join(" / ") || "--"}</div>
              </>
            ),
          },
          {
            key: "application",
            header: "应用",
            widthClassName: "w-[120px]",
            render: (session) => (
              <>
                <div>{session.application || "--"}</div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">{session.transport || "--"}</div>
              </>
            ),
          },
          {
            key: "endpoint",
            header: "端点",
            widthClassName: "w-[180px]",
            render: (session) => (
              <>
                <div className="font-mono">
                  {session.source || "--"}:{session.sourcePort || 0}
                </div>
                <div className="font-mono text-muted-foreground">
                  {session.destination || "--"}:{session.destinationPort || 0}
                </div>
              </>
            ),
          },
          {
            key: "rtp",
            header: "RTP",
            widthClassName: "w-[190px]",
            render: (session) => (
              <>
                <div>{session.codec || "--"}</div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">
                  SSRC {session.ssrc || "--"} / PT {session.payloadType || "--"}
                  {session.clockRate ? ` / ${session.clockRate}` : ""}
                </div>
              </>
            ),
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-[160px]",
            render: (session) => (
              <>
                <div className="font-mono">{session.startTime || "--"}</div>
                <div className="font-mono text-muted-foreground">{session.endTime || "--"}</div>
              </>
            ),
          },
          {
            key: "stats",
            header: "统计",
            widthClassName: "w-[110px]",
            render: (session) => (
              <>
                <div>包数 {session.packetCount.toLocaleString()}</div>
                <div className="text-muted-foreground">丢序 {session.gapCount.toLocaleString()}</div>
              </>
            ),
          },
          {
            key: "control",
            header: "控制面",
            widthClassName: "w-[190px]",
            render: (session) => (
              <>
                <div>{session.controlSummary || "--"}</div>
                {session.notes.length > 0 && (
                  <div className="mt-1 text-[11px] text-muted-foreground">{session.notes.join(" / ")}</div>
                )}
              </>
            ),
          },
          {
            key: "transcription",
            header: "转写",
            widthClassName: "w-[360px]",
            render: (session) => (
              <TranscriptionCell
                session={session}
                batchStatus={batchStatus}
                transcriptions={transcriptions}
                transcriptionLoadingToken={transcriptionLoadingToken}
                transcriptionStartedAt={transcriptionStartedAt}
                batchTokenStartedAt={batchTokenStartedAt}
                progressClock={progressClock}
                onCopyText={onCopyText}
              />
            ),
          },
          {
            key: "export",
            header: "导出",
            widthClassName: "w-[230px]",
            render: (session) => (
              <ExportActionsCell
                session={session}
                batchStatus={batchStatus}
                transcriptionLoadingToken={transcriptionLoadingToken}
                playbackLoadingToken={playbackLoadingToken}
                onDownloadArtifact={onDownloadArtifact}
                onOpenPlayback={onOpenPlayback}
                onRunTranscription={onRunTranscription}
              />
            ),
          },
        ]}
      />
    </Panel>
  );
}
