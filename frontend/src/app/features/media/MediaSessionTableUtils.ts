import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";

const PLAYABLE_VIDEO_FORMATS = new Set(["h264", "264", "h265", "265", "hevc"]);
const PLAYABLE_AUDIO_FORMATS = new Set(["ulaw", "alaw", "g722", "l16", "aac", "opus", "mpa", "mp3"]);

export type TranscriptionProgressTone = "rose" | "amber" | "blue" | "emerald";

export function canPlayArtifact(session: MediaSession): boolean {
  if (!session.artifact) return false;
  const mediaType = (session.mediaType || "").toLowerCase();
  const format = (session.artifact.format || "").toLowerCase();
  if (mediaType === "video") {
    return PLAYABLE_VIDEO_FORMATS.has(format);
  }
  if (mediaType === "audio") {
    return PLAYABLE_AUDIO_FORMATS.has(format);
  }
  return false;
}

export function transcriptionStatusOf(
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

export function transcriptionRecordOf(
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

export function estimateTranscriptionProgress(elapsedMs: number) {
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

export function progressToneClass(tone: TranscriptionProgressTone) {
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
