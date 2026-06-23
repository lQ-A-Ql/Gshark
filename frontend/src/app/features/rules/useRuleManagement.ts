import { useCallback, useEffect, useRef, useState } from "react";
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
  const abortRef = useRef<AbortController | null>(null);

  const resetAbortController = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    return abortRef.current;
  }, []);

  const fetchStatus = useCallback(
    async (signal?: AbortSignal) => {
      if (!backendConnected) return;
      setLoading(true);
      setError(null);
      try {
        setStatus(await backendClients.rules.getRuleStatus(signal));
      } catch (e) {
        if (signal?.aborted) return;
        setError(e instanceof Error ? e.message : "Failed to fetch rule status");
      } finally {
        if (!signal?.aborted) {
          setLoading(false);
        }
      }
    },
    [backendConnected],
  );

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
    async (packId: string, url: string, checksum: string): Promise<RulePack | null> => {
      try {
        const pack = await backendClients.rules.downloadRulePack(packId, url, checksum);
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

  const fetchConflicts = useCallback(async (signal?: AbortSignal): Promise<RuleConflict[]> => {
    try {
      return await backendClients.rules.listRuleConflicts(signal);
    } catch (e) {
      if (signal?.aborted) return [];
      setError(e instanceof Error ? e.message : "Failed to fetch conflicts");
      return [];
    }
  }, []);

  const validateRules = useCallback(
    async (content: string, signal?: AbortSignal): Promise<{ valid: boolean; errors: RuleValidationError[] }> => {
      try {
        return await backendClients.rules.validateRuleContent(content, signal);
      } catch (e) {
        if (signal?.aborted) return { valid: false, errors: [] };
        setError(e instanceof Error ? e.message : "Failed to validate rules");
        return { valid: false, errors: [] };
      }
    },
    [],
  );

  useEffect(() => {
    const controller = resetAbortController();
    void fetchStatus(controller.signal);
    return () => {
      controller.abort();
    };
  }, [fetchStatus, resetAbortController]);

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
