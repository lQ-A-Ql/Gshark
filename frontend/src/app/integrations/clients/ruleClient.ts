type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface RuleVersion {
  major: number;
  minor: number;
  patch: number;
  tag: string;
  released_at: string;
}

export interface RuleEntry {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  enabled: boolean;
}

export interface RulePack {
  id: string;
  name: string;
  description: string;
  source: string;
  version: RuleVersion;
  enabled: boolean;
  rule_count: number;
  checksum: string;
  updated_at: string;
  rules: RuleEntry[];
}

export interface RuleConflict {
  rule_id_1: string;
  rule_id_2: string;
  pack_id_1: string;
  pack_id_2: string;
  conflict: string;
  severity: string;
}

export interface RuleUpdateConfig {
  remote_url: string;
  auto_update: boolean;
  update_interval_hours: number;
  cache_dir: string;
}

export interface RuleStatus {
  packs: RulePack[];
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;
  last_update: string;
  update_config: RuleUpdateConfig;
  conflicts: RuleConflict[];
}

export interface RuleUpdateResult {
  pack_id: string;
  old_version: RuleVersion;
  new_version: RuleVersion;
  updated: boolean;
  downloaded_rules: number;
  error: string;
}

export interface RuleValidationError {
  line: number;
  rule: string;
  message: string;
}

export interface RuleClient {
  getRuleStatus(signal?: AbortSignal): Promise<RuleStatus>;
  toggleRulePack(packId: string, enabled: boolean, signal?: AbortSignal): Promise<void>;
  checkRuleUpdates(signal?: AbortSignal): Promise<RuleUpdateResult[]>;
  downloadRulePack(packId: string, url: string, checksum: string, signal?: AbortSignal): Promise<RulePack>;
  updateRuleConfig(config: RuleUpdateConfig, signal?: AbortSignal): Promise<RuleUpdateConfig>;
  listRuleConflicts(signal?: AbortSignal): Promise<RuleConflict[]>;
  validateRuleContent(
    content: string,
    signal?: AbortSignal,
  ): Promise<{ valid: boolean; errors: RuleValidationError[] }>;
}

export function createRuleClient(request: JsonRequest): RuleClient {
  return {
    async getRuleStatus(signal) {
      return request<RuleStatus>("/api/rules/status", { signal });
    },
    async toggleRulePack(packId, enabled, signal) {
      await request<unknown>("/api/rules/pack/toggle", {
        method: "POST",
        body: JSON.stringify({ pack_id: packId, enabled }),
        signal,
      });
    },
    async checkRuleUpdates(signal) {
      const data = await request<{ results?: RuleUpdateResult[] }>("/api/rules/check-updates", {
        method: "POST",
        signal,
      });
      return data.results ?? [];
    },
    async downloadRulePack(packId, url, checksum, signal) {
      return request<RulePack>("/api/rules/download", {
        method: "POST",
        body: JSON.stringify({ pack_id: packId, url, checksum }),
        signal,
      });
    },
    async updateRuleConfig(config, signal) {
      return request<RuleUpdateConfig>("/api/rules/config", {
        method: "POST",
        body: JSON.stringify(config),
        signal,
      });
    },
    async listRuleConflicts(signal) {
      const data = await request<{ conflicts?: RuleConflict[] }>("/api/rules/conflicts", { signal });
      return data.conflicts ?? [];
    },
    async validateRuleContent(content, signal) {
      return request<{ valid: boolean; errors: RuleValidationError[] }>("/api/rules/validate", {
        method: "POST",
        body: JSON.stringify({ content }),
        signal,
      });
    },
  };
}
