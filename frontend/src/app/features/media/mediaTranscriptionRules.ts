import type { MediaTranscription, SpeechBatchTaskStatus, SpeechToTextStatus } from "../../core/types";

export function isMediaDependencyError(message: string) {
  const lower = message.toLowerCase();
  return lower.includes("vosk") || lower.includes("python") || lower.includes("ffmpeg") || message.includes("模型");
}

export function mergeBatchTranscriptions(
  prev: Record<string, MediaTranscription>,
  status: SpeechBatchTaskStatus,
  speechStatus: SpeechToTextStatus | null,
) {
  const next = { ...prev };
  for (const item of status.items) {
    if (!item.text?.trim()) continue;
    next[item.token] = {
      token: item.token,
      sessionId: item.sessionId,
      title: item.title,
      text: item.text,
      language: speechStatus?.language || "zh-CN",
      engine: speechStatus?.engine || "vosk",
      status: item.status,
      cached: item.cached,
      durationSeconds: prev[item.token]?.durationSeconds ?? 0,
      segments: prev[item.token]?.segments ?? [],
    };
  }
  return next;
}

export function routeMediaWorkflowError(
  err: unknown,
  setError: (message: string) => void,
  setSpeechDialogMessage: (message: string) => void,
  fallback: string,
) {
  const message = err instanceof Error ? err.message : fallback;
  if (isMediaDependencyError(message)) {
    setSpeechDialogMessage(message);
  } else {
    setError(message);
  }
}
