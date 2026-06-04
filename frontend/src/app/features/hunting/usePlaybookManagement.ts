import { useCallback, useEffect, useState } from "react";
import type {
  HuntingPlaybook,
  Hypothesis,
  HypothesisStatus,
  PlaybookRunResult,
  SavedSearch,
} from "../../core/types/huntingPlaybook";
import type { PlaybookClient } from "../../integrations/clients/playbookClient";
import { backendClients } from "../../integrations/backendClients";

export interface UsePlaybookManagementOptions {
  backendConnected: boolean;
  playbookClient?: PlaybookClient;
}

export function usePlaybookManagement({
  backendConnected,
  playbookClient = backendClients.playbook,
}: UsePlaybookManagementOptions) {
  // Playbook state
  const [playbooks, setPlaybooks] = useState<HuntingPlaybook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [playbookRunning, setPlaybookRunning] = useState(false);
  const [lastRunResult, setLastRunResult] = useState<PlaybookRunResult | null>(null);

  // Saved search state
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);

  // Hypothesis state
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [hypothesisFilter, setHypothesisFilter] = useState<HypothesisStatus | "">("");

  // Status
  const [statusText, setStatusText] = useState("");
  const [busy, setBusy] = useState(false);

  // Load playbooks
  const loadPlaybooks = useCallback(async () => {
    if (!backendConnected) return;
    try {
      const list = await playbookClient.listPlaybooks();
      setPlaybooks(list);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "加载剧本失败");
    }
  }, [backendConnected, playbookClient]);

  // Load saved searches
  const loadSavedSearches = useCallback(async () => {
    if (!backendConnected) return;
    try {
      const list = await playbookClient.listSavedSearches();
      setSavedSearches(list);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "加载保存的搜索失败");
    }
  }, [backendConnected, playbookClient]);

  // Load hypotheses
  const loadHypotheses = useCallback(async () => {
    if (!backendConnected) return;
    try {
      const list = await playbookClient.listHypotheses(hypothesisFilter || undefined);
      setHypotheses(list);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "加载假设失败");
    }
  }, [backendConnected, playbookClient, hypothesisFilter]);

  // Run playbook
  const runPlaybook = useCallback(
    async (id: string) => {
      if (!backendConnected || playbookRunning) return;
      setPlaybookRunning(true);
      setStatusText("正在执行剧本...");
      try {
        const result = await playbookClient.runPlaybook(id);
        setLastRunResult(result);
        setStatusText(`剧本执行完成: ${result.totalHits} 条命中`);
        await loadPlaybooks();
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "剧本执行失败");
      } finally {
        setPlaybookRunning(false);
      }
    },
    [backendConnected, playbookRunning, playbookClient, loadPlaybooks],
  );

  // Create playbook
  const createPlaybook = useCallback(
    async (playbook: Partial<HuntingPlaybook>) => {
      if (!backendConnected) return null;
      setBusy(true);
      try {
        const created = await playbookClient.createPlaybook(playbook);
        await loadPlaybooks();
        setStatusText(`剧本已创建: ${created.name}`);
        return created;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "创建剧本失败");
        return null;
      } finally {
        setBusy(false);
      }
    },
    [backendConnected, playbookClient, loadPlaybooks],
  );

  // Delete playbook
  const deletePlaybook = useCallback(
    async (id: string) => {
      if (!backendConnected) return;
      try {
        await playbookClient.deletePlaybook(id);
        await loadPlaybooks();
        if (selectedPlaybook === id) setSelectedPlaybook(null);
        setStatusText("剧本已删除");
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "删除剧本失败");
      }
    },
    [backendConnected, playbookClient, loadPlaybooks, selectedPlaybook],
  );

  // Create saved search
  const createSavedSearch = useCallback(
    async (search: Partial<SavedSearch>) => {
      if (!backendConnected) return null;
      try {
        const created = await playbookClient.createSavedSearch(search);
        await loadSavedSearches();
        setStatusText(`搜索已保存: ${created.name}`);
        return created;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "保存搜索失败");
        return null;
      }
    },
    [backendConnected, playbookClient, loadSavedSearches],
  );

  // Execute saved search
  const executeSavedSearch = useCallback(
    async (id: string) => {
      if (!backendConnected) return null;
      setStatusText("正在执行保存的搜索...");
      try {
        const result = await playbookClient.executeSavedSearch(id);
        setStatusText(`搜索完成: ${result.total} 条命中`);
        return result;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "执行搜索失败");
        return null;
      }
    },
    [backendConnected, playbookClient],
  );

  // Create hypothesis
  const createHypothesis = useCallback(
    async (hypothesis: Partial<Hypothesis>) => {
      if (!backendConnected) return null;
      try {
        const created = await playbookClient.createHypothesis(hypothesis);
        await loadHypotheses();
        setStatusText(`假设已创建: ${created.title}`);
        return created;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "创建假设失败");
        return null;
      }
    },
    [backendConnected, playbookClient, loadHypotheses],
  );

  // Update hypothesis status
  const updateHypothesisStatus = useCallback(
    async (id: string, status: HypothesisStatus, conclusion?: string) => {
      if (!backendConnected) return null;
      try {
        const updated = await playbookClient.updateHypothesisStatus(id, status, conclusion);
        await loadHypotheses();
        setStatusText(`假设状态已更新: ${status}`);
        return updated;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "更新假设状态失败");
        return null;
      }
    },
    [backendConnected, playbookClient, loadHypotheses],
  );

  // Add evidence to hypothesis
  const addHypothesisEvidence = useCallback(
    async (hypothesisId: string, evidence: { description: string; source: string; strength: "supports" | "contradicts" | "neutral" }) => {
      if (!backendConnected) return null;
      try {
        const updated = await playbookClient.addHypothesisEvidence(hypothesisId, evidence);
        await loadHypotheses();
        setStatusText("证据已添加");
        return updated;
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "添加证据失败");
        return null;
      }
    },
    [backendConnected, playbookClient, loadHypotheses],
  );

  // Load data on mount and when filters change
  useEffect(() => {
    void loadPlaybooks();
  }, [loadPlaybooks]);

  useEffect(() => {
    void loadSavedSearches();
  }, [loadSavedSearches]);

  useEffect(() => {
    void loadHypotheses();
  }, [loadHypotheses]);

  return {
    // Playbook
    playbooks,
    selectedPlaybook,
    playbookRunning,
    lastRunResult,
    setSelectedPlaybook,
    runPlaybook,
    createPlaybook,
    deletePlaybook,

    // Saved search
    savedSearches,
    createSavedSearch,
    executeSavedSearch,

    // Hypothesis
    hypotheses,
    hypothesisFilter,
    setHypothesisFilter,
    createHypothesis,
    updateHypothesisStatus,
    addHypothesisEvidence,

    // Status
    statusText,
    busy,
  };
}
