import type { SpeechBatchTaskStatus } from "../../core/types";

export function asSpeechBatchTaskStatus(input: any): SpeechBatchTaskStatus {
  return {
    taskId: String(input?.task_id ?? ""),
    total: Number(input?.total ?? 0),
    queued: Number(input?.queued ?? 0),
    running: Number(input?.running ?? 0),
    completed: Number(input?.completed ?? 0),
    failed: Number(input?.failed ?? 0),
    skipped: Number(input?.skipped ?? 0),
    currentToken: String(input?.current_token ?? "") || undefined,
    currentLabel: String(input?.current_label ?? "") || undefined,
    done: Boolean(input?.done),
    cancelled: Boolean(input?.cancelled),
    items: Array.isArray(input?.items)
      ? input.items.map((item: any) => ({
          token: String(item.token ?? ""),
          sessionId: String(item.session_id ?? ""),
          mediaLabel: String(item.media_label ?? ""),
          title: String(item.title ?? ""),
          status: String(item.status ?? "queued") as SpeechBatchTaskStatus["items"][number]["status"],
          error: String(item.error ?? "") || undefined,
          cached: Boolean(item.cached),
          text: String(item.text ?? "") || undefined,
        }))
      : [],
  };
}
