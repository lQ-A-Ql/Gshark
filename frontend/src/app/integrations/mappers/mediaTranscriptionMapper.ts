import type { MediaTranscription } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asMediaTranscription(input: unknown): MediaTranscription {
  const payload = asPlainObject(input);
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
    segments: asArray(payload?.segments).map((value) => {
      const item = asPlainObject(value);
      return {
        startSeconds: Number(item?.start_seconds ?? 0),
        endSeconds: Number(item?.end_seconds ?? 0),
        text: String(item?.text ?? ""),
      };
    }),
  };
}
