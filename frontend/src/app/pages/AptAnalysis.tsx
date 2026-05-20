import { Crosshair, Database, Network, ShieldAlert, Workflow } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { MetricCard, StatusHint } from "../components/DesignSystem";
import { AnalysisBucketChart, AnalysisMiniStat } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import {
  EvidenceSourceTabs,
  EvidenceTable,
  buildEvidenceSourceTabs,
  evidenceMatchesTab,
  type EvidenceSourceTab,
} from "../features/apt/APTEvidencePanel";
import { AttributionExplainer, NotesPanel } from "../features/apt/APTAttributionPanel";
import {
  ActorEvidenceNeeds,
  ActorTab,
  AptPanel,
  RegistryTagSection,
  StatusBadge,
} from "../features/apt/APTDisplayComponents";
import { EvidenceTimeline } from "../features/apt/APTEvidenceTimeline";
import { buildAPTDisplayProfiles } from "../features/apt/actorRegistry";
import { buildAPTAnalysisCacheKey, useAPTAnalysis } from "../features/apt/useAPTAnalysis";
import { useSentinel } from "../state/SentinelContext";

export default function AptAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [activeActorId, setActiveActorId] = useState("silver-fox");
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<EvidenceSourceTab>("all");
  const handleActiveActorChange = useCallback((actorId: string) => setActiveActorId(actorId), []);
  const { analysis, loading, error, refreshAnalysis } = useAPTAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    activeActorId,
    onActiveActorChange: handleActiveActorChange,
  });

  const displayProfiles = useMemo(() => buildAPTDisplayProfiles(analysis.profiles), [analysis.profiles]);
  const activeProfile = useMemo(
    () => displayProfiles.find((profile) => profile.id === activeActorId) ?? displayProfiles[0],
    [activeActorId, displayProfiles],
  );
  const actorEvidence = useMemo(() => {
    if (!activeProfile) return analysis.evidence;
    if (activeProfile.frameworkOnly) return [];
    return analysis.evidence.filter((item) => item.actorId === activeProfile.id);
  }, [activeProfile, analysis.evidence]);
  const activeEvidence = useMemo(
    () => actorEvidence.filter((item) => evidenceMatchesTab(item, activeEvidenceTab)),
    [actorEvidence, activeEvidenceTab],
  );
  const sourceTabs = useMemo(() => buildEvidenceSourceTabs(actorEvidence), [actorEvidence]);

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  return (
    <PageShell>
      <AnalysisHero
        icon={<Crosshair className="h-5 w-5" />}
        title="APT 组织画像"
        subtitle="APT ACTOR PROFILING"
        description="独立承载组织/活动簇画像，优先消费 C2 样本分析页输出的 actorHints、样本家族、投递阶段、传输特征与基础设施线索；Silver Fox 已接入检测，其它经典组织先作为可复核画像框架展示。"
        tags={["Silver Fox", "Actor Registry", "TTP", "Evidence Caveat"]}
        tagsLabel="画像域"
        theme="indigo"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="indigo">正在加载 APT 组织画像...</StatusHint>}

      {!loading && error && <StatusHint tone="amber">{error}</StatusHint>}

      <div className="gshark-tile-grid grid grid-cols-1 lg:grid-cols-4">
        <MetricCard
          label="组织证据"
          value={analysis.totalEvidence.toLocaleString()}
          icon={<ShieldAlert className="h-4 w-4" />}
          tone="indigo"
        />
        <MetricCard
          label="候选组织"
          value={String(displayProfiles.length)}
          icon={<Crosshair className="h-4 w-4" />}
          tone="rose"
        />
        <MetricCard
          label="样本家族"
          value={String(analysis.sampleFamilies.length)}
          icon={<Database className="h-4 w-4" />}
          tone="cyan"
        />
        <MetricCard
          label="C2 关联"
          value={String(analysis.relatedC2Families.length)}
          icon={<Network className="h-4 w-4" />}
          tone="amber"
        />
      </div>

      <div className="gshark-tile-toolbar p-2">
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {displayProfiles.map((profile) => (
            <ActorTab
              key={profile.id}
              profile={profile}
              active={activeActorId === profile.id}
              onClick={() => setActiveActorId(profile.id)}
            />
          ))}
        </div>
      </div>

      {activeProfile ? (
        <div className="gshark-tile-grid grid grid-cols-1 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
          <AptPanel title={`${activeProfile.name} 画像概览`} icon={<Crosshair className="h-4 w-4 text-indigo-600" />}>
            <div className="space-y-3">
              <div>
                <div className="text-lg font-semibold text-slate-950">{activeProfile.name}</div>
                <div className="mt-1 text-xs text-slate-500">{activeProfile.aliases?.join(" / ") || "暂无别名"}</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <StatusBadge label={activeProfile.registry.statusLabel} tone={activeProfile.registry.statusTone} />
                {activeProfile.frameworkOnly && <StatusBadge label="不参与本轮评分" tone="rose" />}
                {!activeProfile.frameworkOnly && activeProfile.evidenceCount === 0 && (
                  <StatusBadge label="当前抓包未命中" tone="slate" />
                )}
              </div>
              <p className="text-sm leading-6 text-slate-600">{activeProfile.summary}</p>
              <div className="grid gap-3 sm:grid-cols-3">
                <AnalysisMiniStat title="Evidence" value={activeProfile.evidenceCount.toLocaleString()} />
                <AnalysisMiniStat
                  title="Confidence"
                  value={
                    activeProfile.frameworkOnly
                      ? "不评分"
                      : activeProfile.confidence
                        ? `${activeProfile.confidence}%`
                        : "待计算"
                  }
                />
                <AnalysisMiniStat title="C2 Families" value={String(activeProfile.relatedC2Families.length)} />
              </div>
              <RegistryTagSection profile={activeProfile} />
              <NotesPanel notes={activeProfile.notes} emptyText="该组织画像暂无补充说明。" />
            </div>
          </AptPanel>

          <AptPanel title="画像状态与证据需求" icon={<Workflow className="h-4 w-4 text-amber-600" />}>
            <ActorEvidenceNeeds profile={activeProfile} />
          </AptPanel>
        </div>
      ) : null}

      <div className="gshark-tile-grid grid grid-cols-1 xl:grid-cols-3">
        <AptPanel title="样本家族分布">
          <AnalysisBucketChart
            data={activeProfile?.sampleFamilies ?? analysis.sampleFamilies}
            emptyText="尚无样本家族证据，等待 C2 / 样本解析模块输出。"
            barClassName="bg-indigo-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </AptPanel>
        <AptPanel title="投递阶段">
          <AnalysisBucketChart
            data={activeProfile?.campaignStages ?? analysis.campaignStages}
            emptyText="尚无投递链阶段证据。"
            barClassName="bg-rose-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </AptPanel>
        <AptPanel title="传输特征">
          <AnalysisBucketChart
            data={activeProfile?.transportTraits ?? analysis.transportTraits}
            emptyText="尚无 HTTPS/TCP/fallback/周期回连证据。"
            barClassName="bg-cyan-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </AptPanel>
      </div>

      <div className="gshark-tile-grid grid grid-cols-1 xl:grid-cols-2">
        <AptPanel title="基础设施线索">
          <AnalysisBucketChart
            data={activeProfile?.infrastructureHints ?? analysis.infrastructureHints}
            emptyText="尚无 HFS 下载链、fallback C2、端口画像等基础设施线索。"
            barClassName="bg-amber-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </AptPanel>
        <AptPanel title="C2 技术证据来源">
          <AnalysisBucketChart
            data={activeProfile?.relatedC2Families ?? analysis.relatedC2Families}
            emptyText="尚未从 C2 样本分析页收到可关联组织的 CS / VShell 技术证据。"
            barClassName="bg-slate-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </AptPanel>
      </div>

      <AptPanel title="归因解释面板" icon={<ShieldAlert className="h-4 w-4 text-emerald-600" />}>
        <AttributionExplainer profile={activeProfile} evidence={activeEvidence} />
        <EvidenceTimeline evidence={activeEvidence} />
      </AptPanel>

      <AptPanel title={`${activeProfile?.name ?? "APT"} 证据表`}>
        <EvidenceSourceTabs tabs={sourceTabs} active={activeEvidenceTab} onChange={setActiveEvidenceTab} />
        <EvidenceTable profile={activeProfile} evidence={activeEvidence} />
      </AptPanel>

      <AptPanel title="全局 Notes">
        <NotesPanel
          notes={analysis.notes}
          emptyText="当前抓包暂未生成 APT 全局说明；页面会继续展示 registry 画像和缺失证据需求，供后续样本接入复核。"
        />
      </AptPanel>
    </PageShell>
  );
}

export { buildAPTAnalysisCacheKey };
