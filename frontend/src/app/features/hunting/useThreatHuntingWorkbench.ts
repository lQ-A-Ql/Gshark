import { useCallback, useEffect, useMemo, useState } from "react";
import type { ThreatHit } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import type { HuntingRuntimeConfig } from "../../integrations/clients/huntingClient";
import { parseThreatPrefixes } from "./threatHuntingRules";

interface ThreatHuntingClient {
  listThreatHits(prefixes?: string[]): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
}

export interface UseThreatHuntingWorkbenchOptions {
  backendConnected: boolean;
  threatHits: ThreatHit[];
  huntingClient?: ThreatHuntingClient;
}

export function useThreatHuntingWorkbench({
  backendConnected,
  threatHits,
  huntingClient = backendClients.hunting,
}: UseThreatHuntingWorkbenchOptions) {
  const [hits, setHits] = useState(threatHits);
  const [selectedHit, setSelectedHit] = useState<number | null>(threatHits[0]?.id ?? null);
  const [prefixText, setPrefixText] = useState("flag{,ctf{");
  const [yaraEnabled, setYaraEnabled] = useState(true);
  const [yaraBin, setYaraBin] = useState("");
  const [yaraRules, setYaraRules] = useState("");
  const [yaraTimeoutMs, setYaraTimeoutMs] = useState(25000);
  const [configBusy, setConfigBusy] = useState(false);
  const [huntBusy, setHuntBusy] = useState(false);
  const [statusText, setStatusText] = useState("");

  const runHunt = useCallback(
    async (prefixes: string[]) => {
      if (!backendConnected) return;
      setHuntBusy(true);
      try {
        const nextHits = await huntingClient.listThreatHits(prefixes);
        setHits(nextHits);
        setSelectedHit(nextHits[0]?.id ?? null);
        setStatusText(`狩猎完成: ${nextHits.length} 条命中`);
      } catch (error) {
        setStatusText(error instanceof Error ? error.message : "狩猎执行失败");
      } finally {
        setHuntBusy(false);
      }
    },
    [backendConnected, huntingClient],
  );

  const loadConfig = useCallback(async () => {
    if (!backendConnected) return;
    setConfigBusy(true);
    try {
      const cfg = await huntingClient.getHuntingRuntimeConfig();
      setPrefixText((cfg.prefixes.length > 0 ? cfg.prefixes : ["flag{", "ctf{"]).join(","));
      setYaraEnabled(cfg.yaraEnabled);
      setYaraBin(cfg.yaraBin);
      setYaraRules(cfg.yaraRules);
      setYaraTimeoutMs(cfg.yaraTimeoutMs > 0 ? cfg.yaraTimeoutMs : 25000);
      setStatusText("已加载狩猎运行参数");
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "加载狩猎参数失败");
    } finally {
      setConfigBusy(false);
    }
  }, [backendConnected, huntingClient]);

  const applyConfigAndRun = useCallback(async () => {
    if (!backendConnected) return;
    const prefixes = parseThreatPrefixes(prefixText);
    if (prefixes.length === 0) {
      setStatusText("至少需要一个 Prefix（例如 flag{）");
      return;
    }

    setConfigBusy(true);
    try {
      const saved = await huntingClient.updateHuntingRuntimeConfig({
        prefixes,
        yaraEnabled,
        yaraBin: yaraBin.trim(),
        yaraRules: yaraRules.trim(),
        yaraTimeoutMs: Number.isFinite(yaraTimeoutMs) && yaraTimeoutMs > 0 ? Math.floor(yaraTimeoutMs) : 25000,
      });
      setPrefixText(saved.prefixes.join(","));
      setYaraEnabled(saved.yaraEnabled);
      setYaraBin(saved.yaraBin);
      setYaraRules(saved.yaraRules);
      setYaraTimeoutMs(saved.yaraTimeoutMs > 0 ? saved.yaraTimeoutMs : 25000);
      setStatusText("参数已保存，开始重跑狩猎...");
      await runHunt(saved.prefixes);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "保存参数失败");
    } finally {
      setConfigBusy(false);
    }
  }, [backendConnected, huntingClient, prefixText, runHunt, yaraBin, yaraEnabled, yaraRules, yaraTimeoutMs]);

  useEffect(() => {
    setHits(threatHits);
    setSelectedHit((prev) => prev ?? threatHits[0]?.id ?? null);
  }, [threatHits]);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const stats = useMemo(() => {
    const ctf = hits.filter((hit) => hit.category === "CTF").length;
    const owasp = hits.filter((hit) => hit.category === "OWASP").length;
    const anomaly = hits.filter((hit) => hit.category === "Anomaly").length;
    return { ctf, owasp, anomaly };
  }, [hits]);

  return {
    hits,
    selectedHit,
    selected: hits.find((hit) => hit.id === selectedHit) ?? null,
    stats,
    prefixText,
    yaraEnabled,
    yaraBin,
    yaraRules,
    yaraTimeoutMs,
    configBusy,
    huntBusy,
    statusText,
    setSelectedHit,
    setPrefixText,
    setYaraEnabled,
    setYaraBin,
    setYaraRules,
    setYaraTimeoutMs,
    runHunt,
    loadConfig,
    applyConfigAndRun,
  };
}
