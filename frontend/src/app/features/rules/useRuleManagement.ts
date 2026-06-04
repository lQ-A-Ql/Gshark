import { useCallback, useEffect, useState } from "react";
import { useBackend } from "../../state/contexts/BackendContext";

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

export function useRuleManagement() {
  const { backendConnected } = useBackend();
  const [status, setStatus] = useState<RuleStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!backendConnected) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch("/api/rules/status");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setStatus(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch rule status");
    } finally {
      setLoading(false);
    }
  }, [backendConnected]);

  const togglePack = useCallback(
    async (packId: string, enabled: boolean) => {
      try {
        const resp = await fetch("/api/rules/pack/toggle", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pack_id: packId, enabled }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        await fetchStatus();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to toggle pack");
      }
    },
    [fetchStatus],
  );

  const checkUpdates = useCallback(async (): Promise<RuleUpdateResult[]> => {
    try {
      const resp = await fetch("/api/rules/check-updates", { method: "POST" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      await fetchStatus();
      return data.results ?? [];
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to check updates");
      return [];
    }
  }, [fetchStatus]);

  const downloadPack = useCallback(
    async (packId: string, url: string): Promise<RulePack | null> => {
      try {
        const resp = await fetch("/api/rules/download", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pack_id: packId, url }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        await fetchStatus();
        return await resp.json();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to download pack");
        return null;
      }
    },
    [fetchStatus],
  );

  const updateConfig = useCallback(
    async (config: RuleUpdateConfig): Promise<void> => {
      try {
        const resp = await fetch("/api/rules/config", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(config),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        await fetchStatus();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to update config");
      }
    },
    [fetchStatus],
  );

  const fetchConflicts = useCallback(async (): Promise<RuleConflict[]> => {
    try {
      const resp = await fetch("/api/rules/conflicts");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      return data.conflicts ?? [];
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch conflicts");
      return [];
    }
  }, []);

  const validateRules = useCallback(
    async (content: string): Promise<{ valid: boolean; errors: RuleValidationError[] }> => {
      try {
        const resp = await fetch("/api/rules/validate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return await resp.json();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to validate rules");
        return { valid: false, errors: [] };
      }
    },
    [],
  );

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  return {
    status,
    loading,
    error,
    fetchStatus,
    togglePack,
    checkUpdates,
    downloadPack,
    updateConfig,
    fetchConflicts,
    validateRules,
  };
}
