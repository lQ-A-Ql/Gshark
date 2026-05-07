import type { SpeechBatchTaskStatus, ToolRuntimeSnapshot } from "../../core/types";

export function asSpeechBatchTaskStatus(input: any): SpeechBatchTaskStatus {
  return {
    taskId: String(input.task_id ?? ""),
    total: Number(input.total ?? 0),
    queued: Number(input.queued ?? 0),
    running: Number(input.running ?? 0),
    completed: Number(input.completed ?? 0),
    failed: Number(input.failed ?? 0),
    skipped: Number(input.skipped ?? 0),
    currentToken: String(input.current_token ?? "") || undefined,
    currentLabel: String(input.current_label ?? "") || undefined,
    done: Boolean(input.done),
    cancelled: Boolean(input.cancelled),
    items: Array.isArray(input.items)
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

export function asToolRuntimeSnapshot(input: any): ToolRuntimeSnapshot {
  return {
    config: {
      tsharkPath: String(input?.config?.tshark_path ?? ""),
      ffmpegPath: String(input?.config?.ffmpeg_path ?? ""),
      pythonPath: String(input?.config?.python_path ?? ""),
      voskModelPath: String(input?.config?.vosk_model_path ?? ""),
      yaraEnabled: Boolean(input?.config?.yara_enabled),
      yaraBin: String(input?.config?.yara_bin ?? ""),
      yaraRules: String(input?.config?.yara_rules ?? ""),
      yaraTimeoutMs: Number(input?.config?.yara_timeout_ms ?? 0) || 25000,
    },
    tshark: {
      available: Boolean(input?.tshark?.available),
      path: String(input?.tshark?.path ?? ""),
      message: String(input?.tshark?.message ?? ""),
      customPath: String(input?.tshark?.custom_path ?? "") || undefined,
      usingCustomPath: Boolean(input?.tshark?.using_custom_path),
    },
    ffmpeg: {
      available: Boolean(input?.ffmpeg?.available),
      path: String(input?.ffmpeg?.path ?? ""),
      message: String(input?.ffmpeg?.message ?? ""),
      customPath: String(input?.ffmpeg?.custom_path ?? "") || undefined,
      usingCustomPath: Boolean(input?.ffmpeg?.using_custom_path),
    },
    speech: {
      available: Boolean(input?.speech?.available),
      engine: String(input?.speech?.engine ?? ""),
      language: String(input?.speech?.language ?? ""),
      pythonAvailable: Boolean(input?.speech?.python_available),
      pythonCommand: String(input?.speech?.python_command ?? "") || undefined,
      ffmpegAvailable: Boolean(input?.speech?.ffmpeg_available),
      voskAvailable: Boolean(input?.speech?.vosk_available),
      modelAvailable: Boolean(input?.speech?.model_available),
      modelPath: String(input?.speech?.model_path ?? "") || undefined,
      message: String(input?.speech?.message ?? ""),
    },
    yara: {
      available: Boolean(input?.yara?.available),
      enabled: Boolean(input?.yara?.enabled),
      path: String(input?.yara?.path ?? "") || undefined,
      rulePath: String(input?.yara?.rule_path ?? "") || undefined,
      message: String(input?.yara?.message ?? ""),
      lastScanMessage: String(input?.yara?.last_scan_message ?? "") || undefined,
      customBin: String(input?.yara?.custom_bin ?? "") || undefined,
      customRules: String(input?.yara?.custom_rules ?? "") || undefined,
      usingCustomBin: Boolean(input?.yara?.using_custom_bin),
      usingCustomRules: Boolean(input?.yara?.using_custom_rules),
      timeoutMs: Number(input?.yara?.timeout_ms ?? 0) || 25000,
    },
  };
}
