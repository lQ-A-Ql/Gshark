import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ThreatHit } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { backendClients } from "../../integrations/backendClients";
import type { HuntingRuntimeConfig } from "../../integrations/clients/huntingClient";
import { parseThreatPrefixes } from "./threatHuntingRules";

interface ThreatHuntingClient {
  listThreatHits(prefixes?: string[], signal?: AbortSignal): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(signal?: AbortSignal): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig, signal?: AbortSignal): Promise<HuntingRuntimeConfig>;
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
  const huntSeqRef = useRef(0);
  const configSeqRef = useRef(0);
  const mountedRef = useRef(true);
  const resolveHuntRef = useRef<(() => void) | null>(null);
  const resolveConfigRef = useRef<(() => void) | null>(null);
  const { run: runHuntRequest, cancel: cancelHuntRequest } = useAbortableRequest();
  const { run: runConfigRequest, cancel: cancelConfigRequest } = useAbortableRequest();

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const runHunt = useCallback(
    async (prefixes: string[]) => {
      if (!backendConnected) return;
      const requestSeq = ++huntSeqRef.current;
      setHuntBusy(true);
      resolveHuntRef.current?.();
      return new Promise<void>((resolve) => {
        resolveHuntRef.current = resolve;
        runHuntRequest({
          request: (signal) => huntingClient.listThreatHits(prefixes, signal),
          onSuccess: (nextHits) => {
            if (!isCurrentRequest(mountedRef.current, requestSeq, huntSeqRef.current)) return;
            setHits(nextHits);
            setSelectedHit(nextHits[0]?.id ?? null);
            setStatusText(`狩猎完成: ${nextHits.length} 条命中`);
          },
          onError: (error) => {
            if (!isCurrentRequest(mountedRef.current, requestSeq, huntSeqRef.current)) return;
            setStatusText(error instanceof Error ? error.message : "狩猎执行失败");
          },
          onSettled: () => {
            if (isCurrentRequest(mountedRef.current, requestSeq, huntSeqRef.current)) {
              setHuntBusy(false);
            }
            resolveHuntRef.current = null;
            resolve();
          },
        });
      });
    },
    [backendConnected, huntingClient, runHuntRequest],
  );

  const loadConfig = useCallback(async () => {
    if (!backendConnected) return;
    const requestSeq = ++configSeqRef.current;
    setConfigBusy(true);
    resolveConfigRef.current?.();
    return new Promise<void>((resolve) => {
      resolveConfigRef.current = resolve;
      runConfigRequest({
        request: (signal) => huntingClient.getHuntingRuntimeConfig(signal),
        onSuccess: (cfg) => {
          if (!isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) return;
          setPrefixText((cfg.prefixes.length > 0 ? cfg.prefixes : ["flag{", "ctf{"]).join(","));
          setYaraEnabled(cfg.yaraEnabled);
          setYaraBin(cfg.yaraBin);
          setYaraRules(cfg.yaraRules);
          setYaraTimeoutMs(cfg.yaraTimeoutMs > 0 ? cfg.yaraTimeoutMs : 25000);
          setStatusText("已加载狩猎运行参数");
        },
        onError: (error) => {
          if (!isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) return;
          setStatusText(error instanceof Error ? error.message : "加载狩猎参数失败");
        },
        onSettled: () => {
          if (isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) {
            setConfigBusy(false);
          }
          resolveConfigRef.current = null;
          resolve();
        },
      });
    });
  }, [backendConnected, huntingClient, runConfigRequest]);

  const applyConfigAndRun = useCallback(async () => {
    if (!backendConnected) return;
    const prefixes = parseThreatPrefixes(prefixText);
    if (prefixes.length === 0) {
      setStatusText("至少需要一个 Prefix（例如 flag{）");
      return;
    }

    const requestSeq = ++configSeqRef.current;
    setConfigBusy(true);
    resolveConfigRef.current?.();
    return new Promise<void>((resolve) => {
      resolveConfigRef.current = resolve;
      runConfigRequest({
        request: (signal) =>
          huntingClient.updateHuntingRuntimeConfig(
            {
              prefixes,
              yaraEnabled,
              yaraBin: yaraBin.trim(),
              yaraRules: yaraRules.trim(),
              yaraTimeoutMs: Number.isFinite(yaraTimeoutMs) && yaraTimeoutMs > 0 ? Math.floor(yaraTimeoutMs) : 25000,
            },
            signal,
          ),
        onSuccess: (saved) => {
          if (!isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) return;
          setPrefixText(saved.prefixes.join(","));
          setYaraEnabled(saved.yaraEnabled);
          setYaraBin(saved.yaraBin);
          setYaraRules(saved.yaraRules);
          setYaraTimeoutMs(saved.yaraTimeoutMs > 0 ? saved.yaraTimeoutMs : 25000);
          setStatusText("参数已保存，开始重跑狩猎");
          void runHunt(saved.prefixes);
        },
        onError: (error) => {
          if (!isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) return;
          setStatusText(error instanceof Error ? error.message : "保存参数失败");
        },
        onSettled: () => {
          if (isCurrentRequest(mountedRef.current, requestSeq, configSeqRef.current)) {
            setConfigBusy(false);
          }
          resolveConfigRef.current = null;
          resolve();
        },
      });
    });
  }, [backendConnected, huntingClient, prefixText, runHunt, yaraBin, yaraEnabled, yaraRules, yaraTimeoutMs]);

  useEffect(() => {
    setHits(threatHits);
    setSelectedHit((prev) => (prev != null && threatHits.some((hit) => hit.id === prev) ? prev : (threatHits[0]?.id ?? null)));
  }, [threatHits]);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  useEffect(() => () => {
    resolveConfigRef.current?.();
    resolveConfigRef.current = null;
    resolveHuntRef.current?.();
    resolveHuntRef.current = null;
    cancelConfigRequest();
    cancelHuntRequest();
  }, [cancelConfigRequest, cancelHuntRequest]);

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

function isCurrentRequest(mounted: boolean, requestSeq: number, currentSeq: number) {
  return mounted && requestSeq === currentSeq;
}
