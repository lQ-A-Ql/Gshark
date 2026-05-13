export interface ThreatHitWireDTO extends Record<string, unknown> {
  id?: unknown;
  packet_id?: unknown;
  category?: unknown;
  rule?: unknown;
  level?: unknown;
  preview?: unknown;
  match?: unknown;
}

export interface HuntingRuntimeConfigWireDTO extends Record<string, unknown> {
  prefixes?: unknown;
  yara_enabled?: unknown;
  yara_bin?: unknown;
  yara_rules?: unknown;
  yara_timeout_ms?: unknown;
}
