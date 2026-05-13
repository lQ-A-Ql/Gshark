import type { SpeechBatchTaskStatus } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asSpeechBatchTaskStatus(input: unknown): SpeechBatchTaskStatus {
  const payload = asPlainObject(input);
  return {
    taskId: String(payload?.task_id ?? ""),
    total: Number(payload?.total ?? 0),
    queued: Number(payload?.queued ?? 0),
    running: Number(payload?.running ?? 0),
    completed: Number(payload?.completed ?? 0),
    failed: Number(payload?.failed ?? 0),
    skipped: Number(payload?.skipped ?? 0),
    currentToken: String(payload?.current_token ?? "") || undefined,
    currentLabel: String(payload?.current_label ?? "") || undefined,
    done: Boolean(payload?.done),
    cancelled: Boolean(payload?.cancelled),
    items: asArray(payload?.items).map(asSpeechBatchItem),
  };
}

function asSpeechBatchItem(input: unknown): SpeechBatchTaskStatus["items"][number] {
  const item = asPlainObject(input);
  return {
    token: String(item?.token ?? ""),
    sessionId: String(item?.session_id ?? ""),
    mediaLabel: String(item?.media_label ?? ""),
    title: String(item?.title ?? ""),
    status: String(item?.status ?? "queued") as SpeechBatchTaskStatus["items"][number]["status"],
    error: String(item?.error ?? "") || undefined,
    cached: Boolean(item?.cached),
    text: String(item?.text ?? "") || undefined,
  };
}
