import { Headphones } from "lucide-react";
import type { MediaSession, SpeechBatchTaskStatus } from "../../core/types";
import type { MediaAnalysisProgress } from "../../state/hooks/useAnalysisProgress";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../components/ui/alert-dialog";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../components/ui/dialog";

const MEDIA_PROGRESS_STEPS: Array<{
  key: MediaAnalysisProgress["phase"];
  label: string;
}> = [
  { key: "prepare", label: "准备" },
  { key: "scan", label: "扫描" },
  { key: "organize", label: "整理" },
  { key: "rebuild", label: "重建" },
];

interface MediaAnalysisProgressPanelProps {
  progress: MediaAnalysisProgress;
}

export function MediaAnalysisProgressPanel({ progress }: MediaAnalysisProgressPanelProps) {
  if (!progress.active) {
    return null;
  }

  return (
    <div className="mb-3 rounded border border-border bg-card px-3 py-3">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-flex rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 font-medium text-rose-700">
              {progress.phaseLabel || "处理中"}
            </span>
            <span>{Math.round(progress.percent)}%</span>
          </div>
          <div className="mt-1 text-sm font-medium text-foreground">{progress.label || "正在分析媒体流..."}</div>
        </div>
        <div className="shrink-0 text-right text-xs text-muted-foreground">
          {progress.total > 0
            ? `${progress.current.toLocaleString()} / ${progress.total.toLocaleString()}`
            : `${progress.current.toLocaleString()}`}
        </div>
      </div>
      <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
        <div
          className="h-full bg-rose-600 transition-all"
          style={{
            width: `${Math.max(4, Math.min(100, progress.percent || 4))}%`,
          }}
        />
      </div>
      <div className="mb-2 grid grid-cols-4 gap-2 text-[11px] text-muted-foreground">
        {MEDIA_PROGRESS_STEPS.map((item) => {
          const active = progress.phase === item.key;
          const completed =
            ["prepare", "scan", "organize", "rebuild", "complete"].indexOf(progress.phase) >=
            MEDIA_PROGRESS_STEPS.findIndex((step) => step.key === item.key);
          return (
            <div
              key={item.key}
              className={`rounded border px-2 py-1 text-center transition-colors ${
                active
                  ? "border-rose-300 bg-rose-50 text-rose-700"
                  : completed
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                    : "border-border bg-background"
              }`}
            >
              {item.label}
            </div>
          );
        })}
      </div>
      {progress.recent.length > 1 && (
        <div className="space-y-1 text-[11px] text-muted-foreground">
          {progress.recent.slice(0, 3).map((item, index) => (
            <div key={`${item}-${index}`} className="truncate">
              {index === 0 ? "当前" : "最近"}: {item}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface BatchTranscriptionStatusPanelProps {
  batchStatus: SpeechBatchTaskStatus;
}

export function BatchTranscriptionStatusPanel({ batchStatus }: BatchTranscriptionStatusPanelProps) {
  if (!batchStatus.taskId) {
    return null;
  }

  const progress =
    batchStatus.total > 0
      ? ((batchStatus.completed + batchStatus.failed + batchStatus.skipped) / batchStatus.total) * 100
      : 0;

  return (
    <div className="mb-3 rounded border border-border bg-card px-3 py-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">批量音频转写</div>
          <div className="mt-1 text-xs text-muted-foreground">
            {batchStatus.done
              ? batchStatus.cancelled
                ? "任务已取消"
                : "任务已完成"
              : batchStatus.currentLabel
                ? `当前处理：${batchStatus.currentLabel}`
                : "正在准备队列..."}
          </div>
        </div>
        <div className="text-right text-xs text-muted-foreground">
          <div>
            {batchStatus.completed + batchStatus.skipped} / {batchStatus.total}
          </div>
          <div>
            失败 {batchStatus.failed} · 排队 {batchStatus.queued}
          </div>
        </div>
      </div>
      <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
        <div
          className="h-full bg-rose-600 transition-all"
          style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
        />
      </div>
      <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
        <span className="rounded bg-muted px-2 py-1">完成 {batchStatus.completed}</span>
        <span className="rounded bg-muted px-2 py-1">跳过 {batchStatus.skipped}</span>
        <span className="rounded bg-muted px-2 py-1">运行中 {batchStatus.running}</span>
        <span className="rounded bg-muted px-2 py-1">失败 {batchStatus.failed}</span>
      </div>
    </div>
  );
}

interface MediaPlaybackDialogProps {
  playbackSession: MediaSession | null;
  playbackUrl: string;
  onClose: () => void;
}

export function MediaPlaybackDialog({ playbackSession, playbackUrl, onClose }: MediaPlaybackDialogProps) {
  return (
    <Dialog
      open={Boolean(playbackSession)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>媒体播放</DialogTitle>
          <DialogDescription>
            {playbackSession
              ? `${playbackSession.application || "媒体流"} · ${playbackSession.codec || "未知编码"} · ${playbackSession.source}:${playbackSession.sourcePort} -> ${playbackSession.destination}:${playbackSession.destinationPort}`
              : "使用 ffmpeg 将裸流转为浏览器可播放的音视频文件。"}
          </DialogDescription>
        </DialogHeader>
        <div
          className={`overflow-hidden rounded-lg border border-border ${
            playbackSession?.mediaType === "audio"
              ? "bg-gradient-to-br from-slate-50 via-rose-50 to-orange-50 p-6"
              : "bg-black"
          }`}
        >
          {playbackUrl ? (
            playbackSession?.mediaType === "audio" ? (
              <div className="flex min-h-48 flex-col items-center justify-center gap-4 text-center">
                <div className="inline-flex h-16 w-16 items-center justify-center rounded-full bg-white/80 text-rose-600 shadow-sm">
                  <Headphones className="h-8 w-8" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-foreground">{playbackSession.codec || "音频流"}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {playbackSession.source}:{playbackSession.sourcePort} {"->"} {playbackSession.destination}:
                    {playbackSession.destinationPort}
                  </div>
                </div>
                <audio key={playbackUrl} className="w-full max-w-2xl" controls autoPlay src={playbackUrl}>
                  当前环境不支持音频播放。
                </audio>
              </div>
            ) : (
              <video key={playbackUrl} className="aspect-video w-full bg-black" controls autoPlay src={playbackUrl}>
                当前环境不支持视频播放。
              </video>
            )
          ) : (
            <div
              className={`flex items-center justify-center text-sm ${
                playbackSession?.mediaType === "audio" ? "min-h-48 text-muted-foreground" : "aspect-video text-white/70"
              }`}
            >
              正在准备媒体播放...
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

interface MediaDependencyDialogsProps {
  ffmpegDialogMessage: string;
  speechDialogMessage: string;
  onFfmpegDialogMessageChange: (message: string) => void;
  onSpeechDialogMessageChange: (message: string) => void;
}

export function MediaDependencyDialogs({
  ffmpegDialogMessage,
  speechDialogMessage,
  onFfmpegDialogMessageChange,
  onSpeechDialogMessageChange,
}: MediaDependencyDialogsProps) {
  return (
    <>
      <AlertDialog
        open={Boolean(ffmpegDialogMessage)}
        onOpenChange={(open) => {
          if (!open) onFfmpegDialogMessageChange("");
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>缺少 ffmpeg</AlertDialogTitle>
            <AlertDialogDescription>
              {ffmpegDialogMessage || "未在环境变量 PATH 中找到 ffmpeg，请先安装 ffmpeg 并将其加入 PATH。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => onFfmpegDialogMessageChange("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={Boolean(speechDialogMessage)}
        onOpenChange={(open) => {
          if (!open) onSpeechDialogMessageChange("");
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>语音转写不可用</AlertDialogTitle>
            <AlertDialogDescription>
              {speechDialogMessage || "本地语音转写依赖未就绪，请检查 Python、vosk 模块、模型目录与 ffmpeg。"}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction onClick={() => onSpeechDialogMessageChange("")}>我知道了</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
