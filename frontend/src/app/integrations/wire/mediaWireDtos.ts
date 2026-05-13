export interface MediaAnalysisWireDTO extends Record<string, unknown> {
  total_media_packets?: unknown;
  protocols?: unknown;
  applications?: unknown;
  sessions?: unknown;
  notes?: unknown;
}

export interface MediaTranscriptionWireDTO extends Record<string, unknown> {
  token?: unknown;
  session_id?: unknown;
  title?: unknown;
  text?: unknown;
  language?: unknown;
  engine?: unknown;
  status?: unknown;
  error?: unknown;
  cached?: unknown;
  duration_seconds?: unknown;
  segments?: unknown;
}

export interface SpeechBatchTaskStatusWireDTO extends Record<string, unknown> {
  task_id?: unknown;
  total?: unknown;
  queued?: unknown;
  running?: unknown;
  completed?: unknown;
  failed?: unknown;
  skipped?: unknown;
  current_token?: unknown;
  current_label?: unknown;
  done?: unknown;
  cancelled?: unknown;
  items?: unknown;
}
