import { Crosshair, Database, Network, ShieldAlert, Workflow } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { EmptyState, MetricCard, StatusHint } from "../components/DesignSystem";
import { AnalysisBucketChart, AnalysisMiniStat } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { cn } from "../components/ui/utils";
import type { APTEvidenceRecord, APTScoreFactor } from "../core/types";
import { EvidenceSourceTabs, EvidenceTable, buildEvidenceSourceTabs, evidenceMatchesTab, type EvidenceSourceTab } from "../features/apt/APTEvidencePanel";
import { ActorEvidenceNeeds, ActorTab, AptPanel, RegistryTagSection, StatusBadge } from "../features/apt/APTDisplayComponents";
import { buildAPTDisplayProfiles, type APTDisplayProfile } from "../features/apt/actorRegistry";
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
  const activeProfile = useMemo(() => displayProfiles.find((profile) => profile.id === activeActorId) ?? displayProfiles[0], [activeActorId, displayProfiles]);
  const actorEvidence = useMemo(() => {
    if (!activeProfile) return analysis.evidence;
    if (activeProfile.frameworkOnly) return [];
    return analysis.evidence.filter((item) => item.actorId === activeProfile.id);
  }, [activeProfile, analysis.evidence]);
  const activeEvidence = useMemo(() => actorEvidence.filter((item) => evidenceMatchesTab(item, activeEvidenceTab)), [actorEvidence, activeEvidenceTab]);
  const sourceTabs = useMemo(() => buildEvidenceSourceTabs(actorEvidence), [actorEvidence]);

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
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

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label="组织证据" value={analysis.totalEvidence.toLocaleString()} icon={<ShieldAlert className="h-4 w-4" />} tone="indigo" />
        <MetricCard label="候选组织" value={String(displayProfiles.length)} icon={<Crosshair className="h-4 w-4" />} tone="rose" />
        <MetricCard label="样本家族" value={String(analysis.sampleFamilies.length)} icon={<Database className="h-4 w-4" />} tone="cyan" />
        <MetricCard label="C2 关联" value={String(analysis.relatedC2Families.length)} icon={<Network className="h-4 w-4" />} tone="amber" />
      </div>

      <div className="rounded-[28px] border border-white/80 bg-white/90 p-2 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {displayProfiles.map((profile) => (
            <ActorTab key={profile.id} profile={profile} active={activeActorId === profile.id} onClick={() => setActiveActorId(profile.id)} />
          ))}
        </div>
      </div>

      {activeProfile ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(360px,0.8fr)]">
          <AptPanel title={`${activeProfile.name} 画像概览`} icon={<Crosshair className="h-4 w-4 text-indigo-600" />}>
            <div className="space-y-4">
              <div>
                <div className="text-lg font-semibold text-slate-950">{activeProfile.name}</div>
                <div className="mt-1 text-xs text-slate-500">{activeProfile.aliases?.join(" / ") || "暂无别名"}</div>
              </div>
              <div className="flex flex-wrap gap-2">
                <StatusBadge label={activeProfile.registry.statusLabel} tone={activeProfile.registry.statusTone} />
                {activeProfile.frameworkOnly && <StatusBadge label="不参与本轮评分" tone="rose" />}
                {!activeProfile.frameworkOnly && activeProfile.evidenceCount === 0 && <StatusBadge label="当前抓包未命中" tone="slate" />}
              </div>
              <p className="text-sm leading-6 text-slate-600">{activeProfile.summary}</p>
              <div className="grid gap-3 sm:grid-cols-3">
                <AnalysisMiniStat title="Evidence" value={activeProfile.evidenceCount.toLocaleString()} />
                <AnalysisMiniStat title="Confidence" value={activeProfile.frameworkOnly ? "不评分" : activeProfile.confidence ? `${activeProfile.confidence}%` : "待计算"} />
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

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <AptPanel title="样本家族分布">
          <AnalysisBucketChart data={activeProfile?.sampleFamilies ?? analysis.sampleFamilies} emptyText="尚无样本家族证据，等待 C2 / 样本解析模块输出。" barClassName="bg-indigo-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </AptPanel>
        <AptPanel title="投递阶段">
          <AnalysisBucketChart data={activeProfile?.campaignStages ?? analysis.campaignStages} emptyText="尚无投递链阶段证据。" barClassName="bg-rose-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </AptPanel>
        <AptPanel title="传输特征">
          <AnalysisBucketChart data={activeProfile?.transportTraits ?? analysis.transportTraits} emptyText="尚无 HTTPS/TCP/fallback/周期回连证据。" barClassName="bg-cyan-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </AptPanel>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AptPanel title="基础设施线索">
          <AnalysisBucketChart data={activeProfile?.infrastructureHints ?? analysis.infrastructureHints} emptyText="尚无 HFS 下载链、fallback C2、端口画像等基础设施线索。" barClassName="bg-amber-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </AptPanel>
        <AptPanel title="C2 技术证据来源">
          <AnalysisBucketChart data={activeProfile?.relatedC2Families ?? analysis.relatedC2Families} emptyText="尚未从 C2 样本分析页收到可关联组织的 CS / VShell 技术证据。" barClassName="bg-slate-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
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
        <NotesPanel notes={analysis.notes} emptyText="当前抓包暂未生成 APT 全局说明；页面会继续展示 registry 画像和缺失证据需求，供后续样本接入复核。" />
      </AptPanel>
    </PageShell>
  );
}

function TagLine({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-[11px] text-slate-400">--</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600">
          {value}
        </span>
      ))}
    </div>
  );
}

function NotesPanel({ notes, emptyText }: { notes: string[]; emptyText: string }) {
  if (!notes.length) {
    return <EmptyState>{emptyText}</EmptyState>;
  }
  return (
    <div className="space-y-2">
      {notes.map((note, index) => (
        <div key={`${note}-${index}`} className="rounded-2xl border border-indigo-100 bg-indigo-50/60 px-3 py-2 text-xs leading-5 text-indigo-800">
          {note}
        </div>
      ))}
    </div>
  );
}

export { buildAPTAnalysisCacheKey };

function AttributionExplainer({ profile, evidence }: { profile?: APTDisplayProfile; evidence: APTEvidenceRecord[] }) {
  if (!profile) {
    return (
      <EmptyState>
        暂无活跃 actor profile，无法生成归因解释。
      </EmptyState>
    );
  }

  const profileFactors = profile.frameworkOnly ? [] : (profile.scoreFactors ?? []);
  const hasStructuredFactors = profileFactors.length > 0;
  const supportingFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight >= 5);
  const weakFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight < 5);
  const negativeFactors = profileFactors.filter((factor) => factor.direction === "negative");
  const missingFactors = profileFactors.filter((factor) => factor.direction === "missing");
  const supporting = hasStructuredFactors ? supportingFactors : evidence.filter((e) => (e.confidence ?? 0) >= 60);
  const weak = hasStructuredFactors ? weakFactors : evidence.filter((e) => (e.confidence ?? 0) >= 30 && (e.confidence ?? 0) < 60);
  const missing = profile.frameworkOnly
    ? profile.registry.evidenceNeeds.map((summary) => ({ name: summary, summary }))
    : hasStructuredFactors
      ? missingFactors.map(formatAPTScoreFactor)
      : buildMissingEvidence(profile, evidence).map((summary) => ({ name: summary, summary }));
  const caveatCount = profile.frameworkOnly ? profile.registry.caveats.length : negativeFactors.length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <div className="rounded-2xl border border-emerald-100 bg-emerald-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-600">Supporting Evidence</div>
          <div className="mt-1 text-lg font-semibold text-emerald-900">{supporting.length}</div>
          <div className="mt-1 text-[11px] text-emerald-700">{hasStructuredFactors ? "结构化正向评分因子" : "置信度 ≥ 60 的正向证据"}</div>
        </div>
        <div className="rounded-2xl border border-amber-100 bg-amber-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-600">Weak Observations</div>
          <div className="mt-1 text-lg font-semibold text-amber-900">{weak.length}</div>
          <div className="mt-1 text-[11px] text-amber-700">中弱权重或弱观察因子</div>
        </div>
        <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">Missing Evidence</div>
          <div className="mt-1 text-lg font-semibold text-slate-900">{missing.length}</div>
          <div className="mt-1 text-[11px] text-slate-700">基于真实证据动态判断</div>
        </div>
        <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-600">Suppression / Caveat</div>
          <div className="mt-1 text-lg font-semibold text-rose-900">{caveatCount}</div>
          <div className="mt-1 text-[11px] text-rose-700">{profile.frameworkOnly ? "registry caveat 与人工复核提示" : "负向抑制或归因注意事项"}</div>
        </div>
      </div>

      <div className="rounded-2xl border border-indigo-100 bg-indigo-50/30 px-4 py-3">
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-indigo-600">Confidence Rationale</div>
        <div className="mt-2 text-xs leading-5 text-indigo-800">
          {profile.frameworkOnly ? (
            <span>
              {profile.name} 当前为 <strong>{profile.registry.statusLabel}</strong>，只展示画像、证据需求和 caveat，不参与本轮强归因评分；需要补充样本、投递链、C2 与对象证据后再进入评分链路。
            </span>
          ) : profile.confidence && profile.confidence > 0 ? (
            <span>当前置信度 <strong>{profile.confidence}%</strong>，基于 {supporting.length} 个正向因子、{weak.length} 个弱观察、{negativeFactors.length} 个 caveat 与 {missing.length} 个缺失项。</span>
          ) : (
            <span>当前置信度待计算：需要更多 C2 / Threat Hunting / Object 证据流入。</span>
          )}
        </div>
      </div>

      {hasStructuredFactors && (supportingFactors.length > 0 || weakFactors.length > 0 || negativeFactors.length > 0) && (
        <div className="grid gap-3 lg:grid-cols-3">
          <ScoreFactorColumn title="Supporting Evidence" factors={supportingFactors} tone="emerald" />
          <ScoreFactorColumn title="Weak Observations" factors={weakFactors} tone="amber" />
          <ScoreFactorColumn title="Suppression / Caveat" factors={negativeFactors} tone="rose" />
        </div>
      )}

      {missing.length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">Missing Evidence Details</div>
          <div className="mt-2 space-y-1">
            {missing.map((item) => (
              <div key={item.name} className="flex items-start gap-2 text-[11px] text-slate-600">
                <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-slate-400" />
                <span>{item.summary || item.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {profile.frameworkOnly && profile.registry.caveats.length > 0 && (
        <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-4 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-600">Framework Caveat</div>
          <div className="mt-2 space-y-1">
            {profile.registry.caveats.map((item) => (
              <div key={item} className="flex items-start gap-2 text-[11px] leading-5 text-rose-700">
                <span className="mt-1 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-rose-400" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ScoreFactorColumn({ title, factors, tone }: { title: string; factors: APTScoreFactor[]; tone: "emerald" | "amber" | "rose" }) {
  const toneClass = {
    emerald: "border-emerald-100 bg-emerald-50/40 text-emerald-800",
    amber: "border-amber-100 bg-amber-50/40 text-amber-800",
    rose: "border-rose-100 bg-rose-50/40 text-rose-800",
  }[tone];
  return (
    <div className={cn("rounded-2xl border px-4 py-3", toneClass)}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] opacity-80">{title}</div>
      <div className="mt-2 space-y-2">
        {factors.length === 0 ? (
          <div className="text-[11px] opacity-70">--</div>
        ) : factors.map((factor) => (
          <div key={`${factor.sourceModule}-${factor.name}`} className="text-[11px] leading-5">
            <div className="font-semibold">{factor.name} <span className="font-mono opacity-70">{factor.weight > 0 ? "+" : ""}{factor.weight}</span></div>
            <div className="opacity-80">{factor.summary || factor.sourceModule || "structured factor"}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceTimeline({ evidence }: { evidence: APTEvidenceRecord[] }) {
  const sorted = [...evidence].sort((a, b) => {
    const aHasTime = Boolean(a.time);
    const bHasTime = Boolean(b.time);
    if (aHasTime !== bHasTime) return aHasTime ? -1 : 1;
    return String(a.time ?? "").localeCompare(String(b.time ?? ""));
  }).slice(0, 50);

  return (
    <div className="mt-4 rounded-2xl border border-slate-100 bg-white/90 px-4 py-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Evidence Timeline</div>
          <div className="mt-1 text-xs text-slate-500">按当前 actor 与证据来源 tab 排序展示前 50 条；无时间证据置于末尾。</div>
        </div>
        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[10px] text-slate-500">{sorted.length}/{evidence.length}</span>
      </div>
      {sorted.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-4 text-center text-xs text-slate-500">暂无可用于时间线的证据。</div>
      ) : (
        <div className="space-y-2">
          {sorted.map((item, index) => (
            <div key={`${item.packetId}-${item.sourceModule}-${index}`} className="grid gap-3 rounded-xl border border-slate-100 bg-slate-50/60 px-3 py-2 text-xs md:grid-cols-[8rem_minmax(0,1fr)]">
              <div className="font-mono text-[11px] text-slate-500">{item.time || "no-time"}</div>
              <div>
                <div className="font-semibold text-slate-800">{item.sourceModule || "unknown"} · {item.evidenceType || "evidence"} · confidence {item.confidence ?? 0}</div>
                <div className="mt-1 leading-5 text-slate-600">{item.summary || item.evidenceValue || "--"}</div>
                <div className="mt-2"><TagLine values={[...(item.tags ?? []), item.sampleFamily ?? "", item.campaignStage ?? ""].filter(Boolean)} /></div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function buildMissingEvidence(profile: APTDisplayProfile, evidence: APTEvidenceRecord[]): string[] {
  const missing: string[] = [];
  const joinedEvidence = evidence.map((item) => [
    item.sourceModule,
    item.evidenceType,
    item.sampleFamily,
    item.campaignStage,
    ...(item.tags ?? []),
    ...(item.transportTraits ?? []),
    ...(item.infrastructureHints ?? []),
    ...(item.ttpTags ?? []),
    ...(item.scoreFactors ?? []).map((factor) => factor.name),
  ].join(" ").toLowerCase()).join(" ");
  const profileBuckets = [
    ...(profile.sampleFamilies ?? []).map((b) => b.label),
    ...(profile.campaignStages ?? []).map((b) => b.label),
    ...(profile.transportTraits ?? []).map((b) => b.label),
    ...(profile.infrastructureHints ?? []).map((b) => b.label),
  ].join(" ").toLowerCase();
  const corpus = `${joinedEvidence} ${profileBuckets}`;

  if (!/valleyrat|winos|gh0st/.test(corpus)) {
    missing.push("样本家族证据：缺失 ValleyRAT / Winos 4.0 / Gh0st 任一命中");
  }
  if (!/delivery|downloader|hfs-download-chain|rejetto/.test(corpus)) {
    missing.push("投递链证据：缺失 delivery / downloader / HFS 下载链");
  }
  if (!evidence.some((item) => item.sourceModule === "c2-analysis")) {
    missing.push("C2 通信证据：缺失 C2 样本分析来源证据");
  }
  if (!evidence.some((item) => item.sourceModule === "threat-hunting")) {
    missing.push("威胁狩猎证据：缺失 YARA / rule match / anomaly 来源证据");
  }
  if (!evidence.some((item) => item.sourceModule === "object-export")) {
    missing.push("对象 / 文件证据：缺失 Object Export 来源证据");
  }
  const allFactors = evidence.flatMap((item) => item.scoreFactors ?? []);
  if (allFactors.length > 0 && allFactors.every((factor) => factor.name === "silverfox-case-port-weak")) {
    missing.push("归因 caveat：当前仅有端口类弱观察，不能强归因");
  }
  return missing;
}

function formatAPTScoreFactor(factor: APTScoreFactor): { name: string; summary?: string } {
  const prefix = factor.weight ? `${factor.name} (${factor.weight > 0 ? "+" : ""}${factor.weight})` : factor.name;
  return { name: factor.name, summary: factor.summary ? `${prefix}: ${factor.summary}` : prefix };
}
