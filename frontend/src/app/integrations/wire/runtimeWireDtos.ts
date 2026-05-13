export interface ToolRuntimeConfigWireDTO extends Record<string, unknown> {
  tshark_path?: unknown;
  ffmpeg_path?: unknown;
  python_path?: unknown;
  vosk_model_path?: unknown;
  yara_enabled?: unknown;
  yara_bin?: unknown;
  yara_rules?: unknown;
  yara_timeout_ms?: unknown;
}

export interface TSharkStatusWireDTO extends Record<string, unknown> {
  available?: unknown;
  path?: unknown;
  message?: unknown;
  custom_path?: unknown;
  using_custom_path?: unknown;
  version?: unknown;
  field_profile?: unknown;
  field_count?: unknown;
  missing_required_fields?: unknown;
  missing_optional_fields?: unknown;
  capability_message?: unknown;
  capability_check_degraded?: unknown;
}

export interface FFmpegStatusWireDTO extends Record<string, unknown> {
  available?: unknown;
  path?: unknown;
  message?: unknown;
  custom_path?: unknown;
  using_custom_path?: unknown;
}

export interface SpeechStatusWireDTO extends Record<string, unknown> {
  available?: unknown;
  engine?: unknown;
  language?: unknown;
  python_available?: unknown;
  python_command?: unknown;
  ffmpeg_available?: unknown;
  vosk_available?: unknown;
  model_available?: unknown;
  model_path?: unknown;
  message?: unknown;
}

export interface YaraStatusWireDTO extends Record<string, unknown> {
  available?: unknown;
  enabled?: unknown;
  path?: unknown;
  rule_path?: unknown;
  message?: unknown;
  last_scan_message?: unknown;
  custom_bin?: unknown;
  custom_rules?: unknown;
  using_custom_bin?: unknown;
  using_custom_rules?: unknown;
  timeout_ms?: unknown;
}

export interface ToolRuntimeSnapshotWireDTO extends Record<string, unknown> {
  config?: unknown;
  tshark?: unknown;
  ffmpeg?: unknown;
  speech?: unknown;
  yara?: unknown;
}
