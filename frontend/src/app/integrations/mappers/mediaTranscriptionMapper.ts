import type { MediaTranscription } from "../../core/types";

export function asMediaTranscription(payload: any): MediaTranscription {
  return {
    token: String(payload?.token ?? ""),
    sessionId: String(payload?.session_id ?? ""),
    title: String(payload?.title ?? ""),
    text: String(payload?.text ?? ""),
    language: String(payload?.language ?? ""),
    engine: String(payload?.engine ?? ""),
    status: String(payload?.status ?? ""),
    error: String(payload?.error ?? "") || undefined,
    cached: Boolean(payload?.cached),
    durationSeconds: Number(payload?.duration_seconds ?? 0),
    segments: Array.isArray(payload?.segments)
      ? payload.segments.map((item: any) => ({
          startSeconds: Number(item.start_seconds ?? 0),
          endSeconds: Number(item.end_seconds ?? 0),
          text: String(item.text ?? ""),
        }))
      : [],
  };
}
