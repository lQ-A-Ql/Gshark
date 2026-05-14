import { useMemo, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { buildThreatHuntingInvestigationReport } from "../features/hunting/threatHuntingInvestigationReport";
import { ThreatHuntingMetricCards } from "../features/hunting/ThreatHuntingMetricCards";
import {
  ThreatHuntingCategoryPanel,
  ThreatHuntingProgressPanel,
  ThreatHuntingWorkbenchPanel,
} from "../features/hunting/ThreatHuntingPanels";
import {
  buildThreatHuntingProgressView,
  parseThreatPrefixes,
  routeForPreparedStream,
} from "../features/hunting/threatHuntingRules";
import { useThreatHuntingWorkbench } from "../features/hunting/useThreatHuntingWorkbench";
import { useSentinel } from "../state/SentinelContext";

export default function ThreatHunting() {
  const navigate = useNavigate();
  const {
    threatHits,
    backendConnected,
    locatePacketById,
    preparePacketStream,
    isThreatAnalysisLoading,
    threatAnalysisProgress,
  } = useSentinel();
  const [actionBusy, setActionBusy] = useState("");
  const {
    hits,
    selectedHit,
    selected,
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
  } = useThreatHuntingWorkbench({ backendConnected, threatHits });
  const report = useMemo(() => buildThreatHuntingInvestigationReport(hits), [hits]);

  const progress = useMemo(
    () => buildThreatHuntingProgressView({ huntBusy, isThreatAnalysisLoading, progress: threatAnalysisProgress }),
    [huntBusy, isThreatAnalysisLoading, threatAnalysisProgress],
  );

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
      navigate(routeForPreparedStream(prepared.protocol), { state: { streamId: prepared.streamId } });
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
        onRefresh={() => void runHunt(parseThreatPrefixes(prefixText))}
        refreshLabel="重新狩猎"
      />

      <ThreatHuntingMetricCards hits={hits} stats={stats} />

      {progress && <ThreatHuntingProgressPanel progress={progress} />}
      <InvestigationReportPanel className="mt-4" preferredProtocol="TCP" report={report} title="威胁狩猎调查报告" />

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
          onRunWithoutSave={() => runHunt(parseThreatPrefixes(prefixText))}
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
