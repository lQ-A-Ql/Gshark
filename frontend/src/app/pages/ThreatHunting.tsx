import { useEffect, useMemo, useState } from "react";
import { SearchCode, Shield, ShieldAlert, Sparkles } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { MetricCard } from "../components/DesignSystem";
import { PageShell } from "../components/PageShell";
import {
  ThreatHuntingCategoryPanel,
  ThreatHuntingProgressPanel,
  ThreatHuntingWorkbenchPanel,
  type ThreatHuntingProgressView,
} from "../features/hunting/ThreatHuntingPanels";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

export default function ThreatHunting() {
  const navigate = useNavigate();
  const { threatHits, backendConnected, locatePacketById, preparePacketStream, isThreatAnalysisLoading, threatAnalysisProgress } = useSentinel();
  const [hits, setHits] = useState(threatHits);
  const [selectedHit, setSelectedHit] = useState<number | null>(threatHits[0]?.id ?? null);
  const [prefixText, setPrefixText] = useState("flag{,ctf{");
  const [yaraEnabled, setYaraEnabled] = useState(true);
  const [yaraBin, setYaraBin] = useState("");
  const [yaraRules, setYaraRules] = useState("");
  const [yaraTimeoutMs, setYaraTimeoutMs] = useState(25000);
  const [configBusy, setConfigBusy] = useState(false);
  const [huntBusy, setHuntBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const [statusText, setStatusText] = useState("");

  const parsePrefixes = (value: string) =>
    value
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);

  const runHunt = async (prefixes: string[]) => {
    if (!backendConnected) return;
    setHuntBusy(true);
    try {
      const nextHits = await bridge.listThreatHits(prefixes);
      setHits(nextHits);
      setSelectedHit(nextHits[0]?.id ?? null);
      setStatusText(`狩猎完成: ${nextHits.length} 条命中`);
    } catch (error) {
      setStatusText(error instanceof Error ? error.message : "狩猎执行失败");
    } finally {
      setHuntBusy(false);
    }
  };

  const loadConfig = async () => {
    if (!backendConnected) return;
    setConfigBusy(true);
    try {
      const cfg = await bridge.getHuntingRuntimeConfig();
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
  };

  const applyConfigAndRun = async () => {
    if (!backendConnected) return;
    const prefixes = parsePrefixes(prefixText);
    if (prefixes.length === 0) {
      setStatusText("至少需要一个 Prefix（例如 flag{）");
      return;
    }

    setConfigBusy(true);
    try {
      const saved = await bridge.updateHuntingRuntimeConfig({
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
  };

  useEffect(() => {
    setHits(threatHits);
    setSelectedHit((prev) => prev ?? threatHits[0]?.id ?? null);
  }, [threatHits]);

  useEffect(() => {
    void loadConfig();
  }, [backendConnected]);

  const stats = useMemo(() => {
    const ctf = hits.filter((hit) => hit.category === "CTF").length;
    const owasp = hits.filter((hit) => hit.category === "OWASP").length;
    const anomaly = hits.filter((hit) => hit.category === "Anomaly").length;
    return { ctf, owasp, anomaly };
  }, [hits]);

  const progress = useMemo<ThreatHuntingProgressView | null>(() => {
    if (threatAnalysisProgress.active) {
      return {
        title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
        detail: threatAnalysisProgress.label || "正在整理对象、重组流并执行 YARA 扫描。",
        value: Math.max(4, threatAnalysisProgress.percent || 4),
        phaseLabel: threatAnalysisProgress.phaseLabel || "处理中",
        current: threatAnalysisProgress.current,
        total: threatAnalysisProgress.total,
      };
    }
    if (huntBusy || isThreatAnalysisLoading) {
      return {
        title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
        detail: "正在准备威胁分析任务...",
        value: 12,
        phaseLabel: "准备",
        current: 0,
        total: 5,
      };
    }
    return null;
  }, [huntBusy, isThreatAnalysisLoading, threatAnalysisProgress]);

  const selected = hits.find((hit) => hit.id === selectedHit) ?? null;

  const jumpToPacket = async (packetId: number) => {
    setActionBusy(`packet:${packetId}`);
    try {
      await locatePacketById(packetId);
      navigate("/");
    } finally {
      setActionBusy("");
    }
  };

  const openRelatedStream = async (packetId: number) => {
    setActionBusy(`stream:${packetId}`);
    try {
      const prepared = await preparePacketStream(packetId);
      if (!prepared.protocol || prepared.streamId == null) {
        navigate("/");
        return;
      }
      if (prepared.protocol === "HTTP") {
        navigate("/http-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      if (prepared.protocol === "UDP") {
        navigate("/udp-stream", { state: { streamId: prepared.streamId } });
        return;
      }
      navigate("/tcp-stream", { state: { streamId: prepared.streamId } });
    } finally {
      setActionBusy("");
    }
  };

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(96,165,250,0.24),transparent_36%),linear-gradient(180deg,#f7fbff_0%,#f6f7ff_44%,#f8fafc_100%)]"
      innerClassName="max-w-7xl px-6 py-6"
    >
      <AnalysisHero
        icon={<ShieldAlert className="h-5 w-5" />}
        title="威胁狩猎中心"
        subtitle="THREAT HUNTING WORKBENCH"
        description="把 YARA、OWASP、CTF 命中与异常流量汇总到同一工作台，在统一布局中完成规则调参、定位数据包和关联流追踪。"
        tags={["YARA", "OWASP", "CTF", "异常流量"]}
        tagsLabel="狩猎域"
        theme="blue"
        onRefresh={() => void runHunt(parsePrefixes(prefixText))}
        refreshLabel="重新狩猎"
      />

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <MetricCard
          label="总命中"
          value={hits.length.toLocaleString()}
          hint="当前规则集返回的全部命中"
          icon={<SearchCode className="h-4 w-4 text-blue-600" />}
          tone="blue"
        />
        <MetricCard
          label="高风险"
          value={hits.filter((item) => item.level === "critical" || item.level === "high").length.toLocaleString()}
          hint="critical / high 级别命中"
          icon={<Shield className="h-4 w-4 text-rose-600" />}
          tone="rose"
        />
        <MetricCard
          label="CTF / 异常"
          value={`${stats.ctf.toLocaleString()} / ${stats.anomaly.toLocaleString()}`}
          hint="Flag 前缀与异常特征命中"
          icon={<Sparkles className="h-4 w-4 text-amber-600" />}
          tone="amber"
        />
      </div>

      {progress && <ThreatHuntingProgressPanel progress={progress} />}

      <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
        <ThreatHuntingCategoryPanel stats={stats} />
        <ThreatHuntingWorkbenchPanel
          actionBusy={actionBusy}
          backendConnected={backendConnected}
          configBusy={configBusy}
          hits={hits}
          huntBusy={huntBusy}
          prefixText={prefixText}
          selected={selected}
          selectedHit={selectedHit}
          statusText={statusText}
          yaraBin={yaraBin}
          yaraEnabled={yaraEnabled}
          yaraRules={yaraRules}
          yaraTimeoutMs={yaraTimeoutMs}
          onApplyConfigAndRun={applyConfigAndRun}
          onJumpToPacket={jumpToPacket}
          onLoadConfig={loadConfig}
          onOpenRelatedStream={openRelatedStream}
          onPrefixTextChange={setPrefixText}
          onRunWithoutSave={() => runHunt(parsePrefixes(prefixText))}
          onSelectHit={setSelectedHit}
          onYaraBinChange={setYaraBin}
          onYaraEnabledChange={setYaraEnabled}
          onYaraRulesChange={setYaraRules}
          onYaraTimeoutMsChange={setYaraTimeoutMs}
        />
      </div>
    </PageShell>
  );
}
