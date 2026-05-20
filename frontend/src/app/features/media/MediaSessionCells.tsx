import { Copy, Download, FileText, Headphones, Loader2, Play, Video } from "lucide-react";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { formatBytes } from "../../state/formatBytes";
import {
  canPlayArtifact,
  estimateTranscriptionProgress,
  progressToneClass,
  transcriptionRecordOf,
  transcriptionStatusOf,
} from "./MediaSessionTableUtils";

export function MediaTypeBadge({ session }: { session: MediaSession }) {
  const isAudio = (session.mediaType || "video") === "audio";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${
        isAudio ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"
      }`}
    >
      {isAudio ? (
        <>
          <Headphones className="h-3 w-3" /> 音频
        </>
      ) : (
        <>
          <Video className="h-3 w-3" /> 视频
        </>
      )}
    </span>
  );
}

export function TranscriptionCell({
  session,
  batchStatus,
  transcriptions,
  transcriptionLoadingToken,
  transcriptionStartedAt,
  batchTokenStartedAt,
  progressClock,
  onCopyText,
}: {
  session: MediaSession;
  batchStatus: SpeechBatchTaskStatus;
  transcriptions: Record<string, MediaTranscription>;
  transcriptionLoadingToken: string;
  transcriptionStartedAt: number | null;
  batchTokenStartedAt: number | null;
  progressClock: number;
  onCopyText: (text: string) => void | Promise<void>;
}) {
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
  const progress = running && startedAt ? estimateTranscriptionProgress(Math.max(0, progressClock - startedAt)) : null;

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
            className="gshark-soft-fill inline-flex items-center gap-1 px-2 py-0.5 text-[11px] hover:bg-accent"
            onClick={() => void onCopyText(text)}
          >
            <Copy className="h-3 w-3" />
            复制
          </button>
        )}
      </div>
      {text ? (
        <div className="gshark-soft-fill max-w-[28rem] px-2.5 py-2 text-[11px] leading-5 text-emerald-950">
          <div className="line-clamp-4 whitespace-pre-wrap break-words">{text}</div>
        </div>
      ) : progress ? (
        <div className="gshark-soft-fill max-w-[22rem] px-2.5 py-2">
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
        <div className="gshark-soft-fill max-w-[22rem] px-2.5 py-2 text-[11px] leading-5 text-rose-700">
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
}

export function ExportActionsCell({
  session,
  batchStatus,
  transcriptionLoadingToken,
  playbackLoadingToken,
  onDownloadArtifact,
  onOpenPlayback,
  onRunTranscription,
}: {
  session: MediaSession;
  batchStatus: SpeechBatchTaskStatus;
  transcriptionLoadingToken: string;
  playbackLoadingToken: string;
  onDownloadArtifact: (session: MediaSession) => void | Promise<void>;
  onOpenPlayback: (session: MediaSession) => void | Promise<void>;
  onRunTranscription: (session: MediaSession, force?: boolean) => void | Promise<void>;
}) {
  if (!session.artifact) {
    return <span className="text-muted-foreground">未生成</span>;
  }

  const isAudio = (session.mediaType || "").toLowerCase() === "audio";
  const transcriptionRunning =
    transcriptionLoadingToken === session.artifact.token ||
    (!!batchStatus.taskId && !batchStatus.done && batchStatus.currentToken === session.artifact.token);

  return (
    <div className="gshark-soft-fill w-full max-w-[13rem] p-2">
      <div className="flex flex-col gap-2">
        <button
          className="inline-flex w-full items-center justify-center gap-1 rounded-sm border border-slate-200 bg-slate-50/70 px-2.5 py-2 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-100"
          onClick={() => void onDownloadArtifact(session)}
        >
          <Download className="h-3.5 w-3.5" />
          {isAudio ? "下载音频流" : "下载裸流"}
          <span className="text-muted-foreground">({formatBytes(session.artifact.sizeBytes)})</span>
        </button>
        {canPlayArtifact(session) && (
          <button
            className="inline-flex w-full items-center justify-center gap-1 rounded-sm border border-blue-200 bg-blue-50/80 px-2.5 py-2 text-xs font-medium text-blue-700 transition hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
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
        {isAudio && (
          <button
            className="inline-flex w-full items-center justify-center gap-1 rounded-sm border border-emerald-200 bg-emerald-50/80 px-2.5 py-2 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
            onClick={() => void onRunTranscription(session, false)}
            disabled={transcriptionRunning}
          >
            {transcriptionRunning ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileText className="h-3.5 w-3.5" />
            )}
            转写
          </button>
        )}
        <div className="gshark-soft-fill px-2.5 py-2 text-[11px] text-slate-500">
          <div className="truncate font-medium text-slate-700">{session.artifact.name}</div>
          <div className="mt-1">
            {isAudio ? "音频文件已准备好，可下载、播放或直接转写。" : "视频裸流已导出，可继续下载或转为可播放格式。"}
          </div>
        </div>
      </div>
    </div>
  );
}
