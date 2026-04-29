import { Crosshair, Database, Network, ShieldAlert, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { DataTableShell, EmptyState, MetricCard, StatusHint, SurfacePanel } from "../components/DesignSystem";
import { AnalysisBucketChart, AnalysisMiniStat } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { cn } from "../components/ui/utils";
import type { APTActorProfile, APTAnalysis, APTEvidenceRecord, APTScoreFactor } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { EvidenceActions } from "../misc/EvidenceActions";
import { useSentinel } from "../state/SentinelContext";
import { LRUCache } from "../utils/lruCache";

type EvidenceSourceTab = "all" | "c2" | "delivery" | "hunting" | "credential";

const EMPTY_ANALYSIS: APTAnalysis = {
  totalEvidence: 0,
  actors: [],
  sampleFamilies: [],
  campaignStages: [],
  transportTraits: [],
  infrastructureHints: [],
  relatedC2Families: [],
  profiles: [],
  evidence: [],
  notes: [],
};

const aptAnalysisCache = new LRUCache<string, APTAnalysis>(10);

const SILVER_FOX_BASELINE = [
  {
    title: "样本家族",
    text: "预留 ValleyRAT、Winos 4.0、Gh0st 系及其变种证据位；样本家族不直接等同组织归因。",
  },
  {
    title: "投递链",
    text: "预留多阶段投递、下载器、HFS / HTTP File Server 下载链与后续 RAT/C2 串联字段。",
  },
  {
    title: "网络画像",
    text: "预留 HTTPS/TCP C2、fallback C2、长连接、周期回连、自定义高位端口等弱到中等信号。",
  },
];

export default function AptAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [analysis, setAnalysis] = useState<APTAnalysis>(EMPTY_ANALYSIS);
  const [activeActorId, setActiveActorId] = useState("silver-fox");
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<EvidenceSourceTab>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestAbortRef = useRef<AbortController | null>(null);
  const requestSeqRef = useRef(0);

  const cacheKey = useMemo(() => buildAPTAnalysisCacheKey(captureRevision, fileMeta.path, totalPackets), [captureRevision, fileMeta.path, totalPackets]);

  const refreshAnalysis = useCallback((force = false) => {
    if (!fileMeta.path || !backendConnected) {
      setAnalysis(EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    if (!force && cacheKey && aptAnalysisCache.has(cacheKey)) {
      setAnalysis(aptAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    requestAbortRef.current?.abort();
    const abortController = new AbortController();
    requestAbortRef.current = abortController;
    const requestSeq = ++requestSeqRef.current;
    const isLatest = () => requestSeq === requestSeqRef.current;

    void bridge
      .getAPTAnalysis(abortController.signal)
      .then((payload) => {
        if (!isLatest()) return;
        if (cacheKey) {
          aptAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
        if (payload.profiles.length > 0 && !payload.profiles.some((profile) => profile.id === activeActorId)) {
          setActiveActorId(payload.profiles[0].id);
        }
      })
      .catch((err) => {
        if (!isLatest() || abortController.signal.aborted) return;
        setError(err instanceof Error ? err.message : "APT 组织画像加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        if (requestAbortRef.current === abortController) {
          requestAbortRef.current = null;
        }
        if (isLatest()) {
          setLoading(false);
        }
      });

    return () => {
      abortController.abort();
      if (requestAbortRef.current === abortController) {
        requestAbortRef.current = null;
      }
    };
  }, [activeActorId, backendConnected, cacheKey, fileMeta.path]);

  useEffect(() => () => {
    requestAbortRef.current?.abort();
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  const activeProfile = analysis.profiles.find((profile) => profile.id === activeActorId) ?? analysis.profiles[0];
  const actorEvidence = activeProfile ? analysis.evidence.filter((item) => item.actorId === activeProfile.id) : analysis.evidence;
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
        description="独立承载组织/活动簇画像，优先消费 C2 样本分析页输出的 actorHints、样本家族、投递阶段、传输特征与基础设施线索；当前先预置 Silver Fox / 银狐骨架。"
        tags={["Silver Fox", "Actor Profile", "TTP", "Infrastructure"]}
        tagsLabel="画像域"
        theme="indigo"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="indigo">正在加载 APT 组织画像骨架...</StatusHint>}

      {!loading && error && <StatusHint tone="amber">{error}</StatusHint>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label="组织证据" value={analysis.totalEvidence.toLocaleString()} icon={<ShieldAlert className="h-4 w-4" />} tone="indigo" />
        <MetricCard label="候选组织" value={String(analysis.profiles.length)} icon={<Crosshair className="h-4 w-4" />} tone="rose" />
        <MetricCard label="样本家族" value={String(analysis.sampleFamilies.length)} icon={<Database className="h-4 w-4" />} tone="cyan" />
        <MetricCard label="C2 关联" value={String(analysis.relatedC2Families.length)} icon={<Network className="h-4 w-4" />} tone="amber" />
      </div>

      <div className="rounded-[28px] border border-white/80 bg-white/90 p-2 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {analysis.profiles.map((profile) => (
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
              <p className="text-sm leading-6 text-slate-600">{activeProfile.summary}</p>
              <div className="grid gap-3 sm:grid-cols-3">
                <AnalysisMiniStat title="Evidence" value={activeProfile.evidenceCount.toLocaleString()} />
                <AnalysisMiniStat title="Confidence" value={activeProfile.confidence ? `${activeProfile.confidence}%` : "待计算"} />
                <AnalysisMiniStat title="C2 Families" value={String(activeProfile.relatedC2Families.length)} />
              </div>
              <NotesPanel notes={activeProfile.notes} emptyText="该组织画像暂无补充说明。" />
            </div>
          </AptPanel>

          <AptPanel title="Silver Fox 基线预留" icon={<Workflow className="h-4 w-4 text-amber-600" />}>
            <div className="space-y-3">
              {SILVER_FOX_BASELINE.map((item) => (
                <div key={item.title} className="rounded-2xl border border-amber-100 bg-amber-50/70 px-4 py-3">
                  <div className="text-sm font-semibold text-amber-900">{item.title}</div>
                  <p className="mt-1 text-xs leading-5 text-amber-800">{item.text}</p>
                </div>
              ))}
            </div>
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
        <EvidenceTable evidence={activeEvidence} />
      </AptPanel>

      <AptPanel title="全局 Notes">
        <NotesPanel notes={analysis.notes} emptyText="APT 组织画像骨架已就绪，当前抓包暂未生成全局说明。" />
      </AptPanel>
    </PageShell>
  );
}

function EvidenceSourceTabs({ tabs, active, onChange }: { tabs: Array<{ id: EvidenceSourceTab; label: string; count: number }>; active: EvidenceSourceTab; onChange: (tab: EvidenceSourceTab) => void }) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={cn(
            "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition",
            active === tab.id
              ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm"
              : "border-slate-200 bg-white text-slate-600 hover:border-indigo-100 hover:bg-indigo-50/50",
          )}
        >
          <span>{tab.label}</span>
          <span className="rounded-full bg-white/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">{tab.count}</span>
        </button>
      ))}
    </div>
  );
}

function ActorTab({ profile, active, onClick }: { profile: APTActorProfile; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-[22px] border px-4 py-3 text-left transition-all",
        active
          ? "border-indigo-200 bg-indigo-50 text-indigo-900 shadow-[0_18px_50px_-34px_rgba(79,70,229,0.55)]"
          : "border-slate-200 bg-white text-slate-700 hover:border-indigo-100 hover:bg-indigo-50/40",
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="font-semibold">{profile.name}</div>
        <span className="rounded-full border border-white/80 bg-white px-2 py-0.5 text-[11px] text-slate-500">{profile.evidenceCount}</span>
      </div>
      <div className="mt-1 truncate text-xs text-slate-500">{profile.aliases?.join(" / ") || "actor profile"}</div>
    </button>
  );
}

function AptPanel({ title, children, icon, className }: { title: string; children: ReactNode; icon?: ReactNode; className?: string }) {
  return (
    <SurfacePanel title={title} icon={icon ?? <ShieldAlert className="h-4 w-4 text-indigo-600" />} className={className}>
      {children}
    </SurfacePanel>
  );
}

function EvidenceTable({ evidence }: { evidence: APTEvidenceRecord[] }) {
  if (!evidence.length) {
    return (
      <EmptyState className="py-8">
        暂无 APT 归因证据。当前页面只预置组织画像骨架；后续由 C2 样本分析、对象提取、威胁狩猎和样本解析模块共同填充。
      </EmptyState>
    );
  }
  return (
    <DataTableShell maxHeight={460}>
      <table className="min-w-full divide-y divide-slate-100 text-left text-xs">
        <thead className="bg-slate-50 text-slate-500">
          <tr>
            <th className="px-3 py-2">Actor / Type</th>
            <th className="px-3 py-2">Evidence</th>
            <th className="px-3 py-2">Network</th>
            <th className="px-3 py-2">Traits</th>
            <th className="px-3 py-2">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 bg-white">
          {evidence.map((item, index) => (
            <tr key={`${item.packetId}-${item.actorId}-${index}`} className="align-top hover:bg-indigo-50/20">
              <td className="space-y-1 px-3 py-2">
                <div className="font-semibold text-slate-800">{item.actorName || "--"}</div>
                <div className="font-mono text-[11px] text-slate-500">{item.sourceModule || "--"} · {item.evidenceType || "--"} · confidence {item.confidence ?? 0}</div>
              </td>
              <td className="space-y-1 px-3 py-2">
                <div className="text-slate-700">{item.summary}</div>
                <div className="font-mono text-[11px] text-slate-500">{item.evidenceValue || item.evidence || "--"}</div>
              </td>
              <td className="space-y-1 px-3 py-2 font-mono text-[11px] text-slate-500">
                <div>{item.source || "--"} → {item.destination || "--"}</div>
                <div>{item.host || ""}{item.uri || ""}</div>
              </td>
              <td className="px-3 py-2">
                <TagLine values={[item.sampleFamily ?? "", item.campaignStage ?? "", ...(item.transportTraits ?? []), ...(item.infrastructureHints ?? []), ...(item.ttpTags ?? []), ...(item.scoreFactors ?? []).map((factor) => `${factor.name}:${factor.weight}`)].filter(Boolean)} />
              </td>
              <td className="px-3 py-2">
                <EvidenceActions packetId={item.packetId} preferredProtocol={protocolForEvidence(item.family)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </DataTableShell>
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

function protocolForEvidence(family?: string): "HTTP" | "TCP" | "UDP" {
  if (String(family ?? "").toLowerCase().includes("dns")) return "UDP";
  return "HTTP";
}

function buildEvidenceSourceTabs(evidence: APTEvidenceRecord[]): Array<{ id: EvidenceSourceTab; label: string; count: number }> {
  return [
    { id: "all", label: "全部证据", count: evidence.length },
    { id: "c2", label: "C2 Evidence", count: evidence.filter((item) => evidenceMatchesTab(item, "c2")).length },
    { id: "delivery", label: "Delivery / Object", count: evidence.filter((item) => evidenceMatchesTab(item, "delivery")).length },
    { id: "hunting", label: "Threat Hunting", count: evidence.filter((item) => evidenceMatchesTab(item, "hunting")).length },
    { id: "credential", label: "Credential / Auth", count: evidence.filter((item) => evidenceMatchesTab(item, "credential")).length },
  ];
}

function evidenceMatchesTab(item: APTEvidenceRecord, tab: EvidenceSourceTab) {
  if (tab === "all") return true;
  const source = String(item.sourceModule ?? "").toLowerCase();
  const family = String(item.family ?? "").toLowerCase();
  const campaignStage = String(item.campaignStage ?? "").toLowerCase();
  const evidenceType = String(item.evidenceType ?? "").toLowerCase();
  const tags = [...(item.tags ?? []), ...(item.infrastructureHints ?? []), ...(item.ttpTags ?? []), ...(item.transportTraits ?? [])]
    .join(" ")
    .toLowerCase();
  if (tab === "c2") {
    return source.includes("c2") || family === "cs" || family === "vshell";
  }
  if (tab === "delivery") {
    return campaignStage.includes("deliver") || campaignStage.includes("download") || tags.includes("hfs") || tags.includes("delivery");
  }
  if (tab === "hunting") {
    return source.includes("hunting") || tags.includes("yara") || tags.includes("threat");
  }
  if (tab === "credential") {
    return source.includes("credential") || source.includes("auth") || evidenceType.includes("login") || evidenceType.includes("ntlm") || tags.includes("credential");
  }
  return true;
}

export function buildAPTAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}

function AttributionExplainer({ profile, evidence }: { profile?: APTActorProfile; evidence: APTEvidenceRecord[] }) {
  if (!profile) {
    return (
      <EmptyState>
        暂无活跃 actor profile，无法生成归因解释。
      </EmptyState>
    );
  }

  const profileFactors = profile.scoreFactors ?? [];
  const hasStructuredFactors = profileFactors.length > 0;
  const supportingFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight >= 5);
  const weakFactors = profileFactors.filter((factor) => factor.direction === "positive" && factor.weight < 5);
  const negativeFactors = profileFactors.filter((factor) => factor.direction === "negative");
  const missingFactors = profileFactors.filter((factor) => factor.direction === "missing");
  const supporting = hasStructuredFactors ? supportingFactors : evidence.filter((e) => (e.confidence ?? 0) >= 60);
  const weak = hasStructuredFactors ? weakFactors : evidence.filter((e) => (e.confidence ?? 0) >= 30 && (e.confidence ?? 0) < 60);
  const missing = hasStructuredFactors ? missingFactors.map(formatAPTScoreFactor) : buildMissingEvidence(profile, evidence).map((summary) => ({ name: summary, summary }));

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
          <div className="mt-1 text-lg font-semibold text-rose-900">{negativeFactors.length}</div>
          <div className="mt-1 text-[11px] text-rose-700">负向抑制或归因注意事项</div>
        </div>
      </div>

      <div className="rounded-2xl border border-indigo-100 bg-indigo-50/30 px-4 py-3">
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-indigo-600">Confidence Rationale</div>
        <div className="mt-2 text-xs leading-5 text-indigo-800">
          {profile.confidence && profile.confidence > 0 ? (
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

function buildMissingEvidence(profile: APTActorProfile, evidence: APTEvidenceRecord[]): string[] {
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
