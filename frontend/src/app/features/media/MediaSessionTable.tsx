import { Clapperboard, Copy, Download, FileText, Headphones, Loader2, Play, Video } from "lucide-react";
import { useMemo, useState } from "react";
import { AnalysisDataTable as DataTable, AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { formatBytes } from "../../state/SentinelContext";

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

function canPlayArtifact(session: MediaSession): boolean {
  if (!session.artifact) return false;
  const mediaType = (session.mediaType || "").toLowerCase();
  const format = (session.artifact.format || "").toLowerCase();
  if (mediaType === "video") {
    return format === "h264" || format === "264" || format === "h265" || format === "265" || format === "hevc";
  }
  if (mediaType === "audio") {
    return (
      format === "ulaw" ||
      format === "alaw" ||
      format === "g722" ||
      format === "l16" ||
      format === "aac" ||
      format === "opus" ||
      format === "mpa" ||
      format === "mp3"
    );
  }
  return false;
}

function transcriptionStatusOf(
  session: MediaSession,
  batchStatus: SpeechBatchTaskStatus,
  transcriptions: Record<string, MediaTranscription>,
) {
  const token = session.artifact?.token;
  if (!token) return { status: "missing", label: "未生成", className: "bg-muted text-muted-foreground" };
  const batchItem = batchStatus.items.find((item) => item.token === token);
  if (batchItem) {
    switch (batchItem.status) {
      case "queued":
        return { status: "queued", label: "排队中", className: "bg-slate-100 text-slate-700" };
      case "running":
        return { status: "running", label: "转写中", className: "bg-blue-100 text-blue-700" };
      case "completed":
        return { status: "completed", label: "已完成", className: "bg-emerald-100 text-emerald-700" };
      case "failed":
        return { status: "failed", label: "失败", className: "bg-rose-100 text-rose-700" };
      case "skipped":
        return { status: "skipped", label: "已跳过（缓存）", className: "bg-amber-100 text-amber-700" };
    }
  }
  if (transcriptions[token]) {
    return { status: "completed", label: "已完成", className: "bg-emerald-100 text-emerald-700" };
  }
  return { status: "idle", label: "未转写", className: "bg-muted text-muted-foreground" };
}

function transcriptionRecordOf(
  session: MediaSession,
  batchStatus: SpeechBatchTaskStatus,
  transcriptions: Record<string, MediaTranscription>,
) {
  const token = session.artifact?.token;
  if (!token) return null;
  const cached = transcriptions[token];
  if (cached) {
    return {
      text: cached.text || "",
      error: cached.error || "",
      status: cached.status || "completed",
      cached: cached.cached,
    };
  }
  const batchItem = batchStatus.items.find((item) => item.token === token);
  if (!batchItem) return null;
  return {
    text: batchItem.text || "",
    error: batchItem.error || "",
    status: batchItem.status || "idle",
    cached: batchItem.cached,
  };
}

function estimateTranscriptionProgress(elapsedMs: number) {
  if (elapsedMs < 800) {
    return { percent: 14, label: "正在准备音频", tone: "rose" as const };
  }
  if (elapsedMs < 2600) {
    return { percent: 38, label: "正在转码为识别输入", tone: "amber" as const };
  }
  if (elapsedMs < 9000) {
    return { percent: 76, label: "正在进行离线转写", tone: "blue" as const };
  }
  return { percent: 92, label: "正在整理转写结果", tone: "emerald" as const };
}

function progressToneClass(tone: "rose" | "amber" | "blue" | "emerald") {
  switch (tone) {
    case "rose":
      return "bg-rose-500";
    case "amber":
      return "bg-amber-500";
    case "blue":
      return "bg-blue-500";
    case "emerald":
      return "bg-emerald-500";
  }
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
            render: (session) => (
              <span
                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${
                  (session.mediaType || "video") === "audio"
                    ? "bg-purple-100 text-purple-700"
                    : "bg-blue-100 text-blue-700"
                }`}
              >
                {(session.mediaType || "video") === "audio" ? (
                  <>
                    <Headphones className="h-3 w-3" /> 音频
                  </>
                ) : (
                  <>
                    <Video className="h-3 w-3" /> 视频
                  </>
                )}
              </span>
            ),
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
            render: (session) => {
              const mediaType = (session.mediaType || "").toLowerCase();
              if (mediaType !== "audio") {
                return <span className="text-muted-foreground">仅音频支持</span>;
              }
              if (!session.artifact) {
                return <span className="text-muted-foreground">音频流未导出</span>;
              }
              const transcriptionStatus = transcriptionStatusOf(session, batchStatus, transcriptions);
              const record = transcriptionRecordOf(session, batchStatus, transcriptions);
              const text = (record?.text || "").trim();
              const errorText = (record?.error || "").trim();
              const singleRunning = transcriptionLoadingToken === session.artifact.token;
              const batchRunning =
                !!batchStatus.currentToken && batchStatus.currentToken === session.artifact.token && !batchStatus.done;
              const running = singleRunning || batchRunning;
              const startedAt = singleRunning ? transcriptionStartedAt : batchRunning ? batchTokenStartedAt : null;
              const progress =
                running && startedAt ? estimateTranscriptionProgress(Math.max(0, progressClock - startedAt)) : null;
              return (
                <div className="min-w-0 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${transcriptionStatus.className}`}
                    >
                      {transcriptionStatus.label}
                    </span>
                    {record?.cached && transcriptionStatus.status === "completed" && (
                      <span className="inline-flex items-center rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-700">
                        缓存
                      </span>
                    )}
                    {text && (
                      <button
                        className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-0.5 text-[11px] hover:bg-accent"
                        onClick={() => void onCopyText(text)}
                      >
                        <Copy className="h-3 w-3" />
                        复制
                      </button>
                    )}
                  </div>
                  {text ? (
                    <div className="max-w-[28rem] rounded border border-emerald-200 bg-emerald-50 px-2.5 py-2 text-[11px] leading-5 text-emerald-950">
                      <div className="line-clamp-4 whitespace-pre-wrap break-words">{text}</div>
                    </div>
                  ) : progress ? (
                    <div className="max-w-[22rem] rounded border border-slate-200 bg-slate-50 px-2.5 py-2">
                      <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px] text-slate-600">
                        <span>{progress.label}</span>
                        <span>{progress.percent}%</span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-slate-200">
                        <div
                          className={`h-full transition-all ${progressToneClass(progress.tone)}`}
                          style={{ width: `${progress.percent}%` }}
                        />
                      </div>
                    </div>
                  ) : errorText ? (
                    <div className="max-w-[22rem] rounded border border-rose-200 bg-rose-50 px-2.5 py-2 text-[11px] leading-5 text-rose-700">
                      {errorText}
                    </div>
                  ) : (
                    <div className="text-[11px] text-muted-foreground">
                      {transcriptionStatus.status === "idle"
                        ? "点右侧“转写”后，结果会直接显示在这里。"
                        : transcriptionStatus.status === "completed"
                          ? "转写已完成，但这段音频暂时没有识别出可显示的文字。"
                          : "正在等待转写任务进入这一条音频。"}
                    </div>
                  )}
                </div>
              );
            },
          },
          {
            key: "export",
            header: "导出",
            widthClassName: "w-[230px]",
            render: (session) =>
              session.artifact ? (
                <div className="w-full max-w-[13rem] rounded-2xl border border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.98))] p-2 shadow-sm">
                  <div className="flex flex-col gap-2">
                    <button
                      className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-slate-200 bg-white px-2.5 py-2 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50"
                      onClick={() => void onDownloadArtifact(session)}
                    >
                      <Download className="h-3.5 w-3.5" />
                      {(session.mediaType || "").toLowerCase() === "audio" ? "下载音频流" : "下载裸流"}
                      <span className="text-muted-foreground">({formatBytes(session.artifact.sizeBytes)})</span>
                    </button>
                    {canPlayArtifact(session) && (
                      <button
                        className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-blue-200 bg-blue-50 px-2.5 py-2 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                        onClick={() => void onOpenPlayback(session)}
                        disabled={playbackLoadingToken === session.artifact.token}
                      >
                        {playbackLoadingToken === session.artifact.token ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Play className="h-3.5 w-3.5" />
                        )}
                        播放
                      </button>
                    )}
                    {(session.mediaType || "").toLowerCase() === "audio" && (
                      <button
                        className="inline-flex w-full items-center justify-center gap-1 rounded-xl border border-emerald-200 bg-emerald-50 px-2.5 py-2 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
                        onClick={() => void onRunTranscription(session, false)}
                        disabled={
                          transcriptionLoadingToken === session.artifact.token ||
                          (!!batchStatus.taskId &&
                            !batchStatus.done &&
                            batchStatus.currentToken === session.artifact.token)
                        }
                      >
                        {transcriptionLoadingToken === session.artifact.token ||
                        (!!batchStatus.taskId &&
                          !batchStatus.done &&
                          batchStatus.currentToken === session.artifact.token) ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <FileText className="h-3.5 w-3.5" />
                        )}
                        转写
                      </button>
                    )}
                    <div className="rounded-xl bg-slate-50 px-2.5 py-2 text-[11px] text-slate-500">
                      <div className="truncate font-medium text-slate-700">{session.artifact.name}</div>
                      <div className="mt-1">
                        {(session.mediaType || "").toLowerCase() === "audio"
                          ? "音频文件已准备好，可下载、播放或直接转写。"
                          : "视频裸流已导出，可继续下载或转为可播放格式。"}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <span className="text-muted-foreground">未生成</span>
              ),
          },
        ]}
      />
    </Panel>
  );
}
