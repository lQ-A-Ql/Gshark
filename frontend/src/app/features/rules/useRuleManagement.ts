import { useCallback, useEffect, useState } from "react";
import { useBackend } from "../../state/contexts/BackendContext";
import { backendClients } from "../../integrations/backendClients";
import type {
  RuleConflict,
  RulePack,
  RuleStatus,
  RuleUpdateConfig,
  RuleUpdateResult,
  RuleValidationError,
  RuleVersion,
  RuleEntry,
} from "../../integrations/clients/ruleClient";

export type { RuleConflict, RuleEntry, RulePack, RuleStatus, RuleUpdateConfig, RuleUpdateResult, RuleValidationError, RuleVersion };

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
      setStatus(await backendClients.rules.getRuleStatus());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch rule status");
    } finally {
      setLoading(false);
    }
  }, [backendConnected]);

  const togglePack = useCallback(
    async (packId: string, enabled: boolean) => {
      try {
        await backendClients.rules.toggleRulePack(packId, enabled);
        await fetchStatus();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to toggle pack");
      }
    },
    [fetchStatus],
  );

  const checkUpdates = useCallback(async (): Promise<RuleUpdateResult[]> => {
    try {
      const results = await backendClients.rules.checkRuleUpdates();
      await fetchStatus();
      return results;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to check updates");
      return [];
    }
  }, [fetchStatus]);

  const downloadPack = useCallback(
    async (packId: string, url: string): Promise<RulePack | null> => {
      try {
        const pack = await backendClients.rules.downloadRulePack(packId, url);
        await fetchStatus();
        return pack;
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
        await backendClients.rules.updateRuleConfig(config);
        await fetchStatus();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to update config");
      }
    },
    [fetchStatus],
  );

  const fetchConflicts = useCallback(async (): Promise<RuleConflict[]> => {
    try {
      return await backendClients.rules.listRuleConflicts();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch conflicts");
      return [];
    }
  }, []);

  const validateRules = useCallback(
    async (content: string): Promise<{ valid: boolean; errors: RuleValidationError[] }> => {
      try {
        return await backendClients.rules.validateRuleContent(content);
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
