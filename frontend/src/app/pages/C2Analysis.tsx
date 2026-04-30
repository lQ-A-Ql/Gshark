import { Activity, Bug, ChevronDown, ChevronRight, Network, Radio, Server, Shield, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { EmptyState, MetricCard, StatusHint, SurfacePanel } from "../components/DesignSystem";
import { AnalysisBucketChart, AnalysisDataTable as DataTable, AnalysisList } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { Sparkline } from "../components/Sparkline";
import { cn } from "../components/ui/utils";
import type { C2DNSAggregate, C2FamilyAnalysis, C2HTTPEndpointAggregate, C2IndicatorRecord, C2SampleAnalysis, C2StreamAggregate } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { EvidenceActions } from "../misc/EvidenceActions";
import { FilterActions } from "../misc/FilterActions";
import { useSentinel } from "../state/SentinelContext";
import { LRUCache } from "../utils/lruCache";

type C2Tab = "cs" | "vshell";

const EMPTY_FAMILY: C2FamilyAnalysis = {
  candidateCount: 0,
  matchedRuleCount: 0,
  channels: [],
  indicators: [],
  conversations: [],
  beaconPatterns: [],
  hostUriAggregates: [],
  dnsAggregates: [],
  streamAggregates: [],
  candidates: [],
  notes: [],
  relatedActors: [],
  deliveryChains: [],
};

const EMPTY_ANALYSIS: C2SampleAnalysis = {
  totalMatchedPackets: 0,
  families: [],
  conversations: [],
  cs: EMPTY_FAMILY,
  vshell: EMPTY_FAMILY,
  notes: [],
};

const c2AnalysisCache = new LRUCache<string, C2SampleAnalysis>(10);
const C2_TABLE_WRAPPER_CLASS = "border-slate-200 bg-white shadow-sm";
const C2_TABLE_HEADER_CLASS = "bg-gradient-to-r from-slate-100 to-rose-50 text-slate-700";
const C2_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-white even:bg-slate-50/45";
const C2_MONO_CELL_CLASS = "font-mono text-slate-600";

const CS_BASELINE = [
  {
    title: "HTTP/HTTPS Beacon",
    text: "预留 GET 拉任务、POST 回传、Host/URI/UA/Header hints 字段；静态路径只作为弱信号。",
  },
  {
    title: "Sleep / Jitter",
    text: "预留固定或近固定间隔、同端点重复通信、周期回连统计等行为型证据。",
  },
  {
    title: "DNS / SMB Channel",
    text: "预留 DNS qname、qtype、label 长度，以及 SMB pivot / named pipe 候选位。",
  },
];

const VSHELL_BASELINE = [
  {
    title: "多 Listener 通道",
    text: "预留 TCP、KCP/UDP、WebSocket、DNS、DoH、DoT、OSS 等 channel 统计。",
  },
  {
    title: "TCP 心跳画像",
    text: "预留 l64/w64 架构标记、4 字节长度前缀、短长包交替和约 10 秒心跳字段。",
  },
  {
    title: "WebSocket 握手",
    text: "预留 /?a=&h=&t=&p= 参数拆解位，承载 ws_ 通道与 listener port 观察。",
  },
];

const SILVER_FOX_BASELINE = [
  "已预埋 actorHints / sampleFamily / campaignStage，后续可将 ValleyRAT、Winos 4.0、Gh0st 系变种证据交给独立 APT 页。",
  "已预埋 transportTraits / infrastructureHints，后续可承载 HTTPS/TCP C2、HFS 下载链、fallback C2 与周期回连线索。",
  "端口 18856 / 9899 / 443 和 60 秒回连仅作为样本案例观察位，不作为独立强签名。",
];

export default function C2Analysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [analysis, setAnalysis] = useState<C2SampleAnalysis>(EMPTY_ANALYSIS);
  const [activeTab, setActiveTab] = useState<C2Tab>("cs");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestAbortRef = useRef<AbortController | null>(null);
  const requestSeqRef = useRef(0);

  const cacheKey = useMemo(() => {
    return buildC2SampleAnalysisCacheKey(captureRevision, fileMeta.path, totalPackets);
  }, [captureRevision, fileMeta.path, totalPackets]);

  const refreshAnalysis = useCallback((force = false) => {
    if (!fileMeta.path) {
      setAnalysis(EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    if (!backendConnected) {
      setAnalysis(EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    if (!force && cacheKey && c2AnalysisCache.has(cacheKey)) {
      setAnalysis(c2AnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
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
      .getC2SampleAnalysis(abortController.signal)
      .then((payload) => {
        if (!isLatest()) return;
        if (cacheKey) {
          c2AnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        if (!isLatest() || abortController.signal.aborted) return;
        setError(err instanceof Error ? err.message : "C2 样本分析加载失败");
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
  }, [backendConnected, cacheKey, fileMeta.path]);

  useEffect(() => () => {
    requestAbortRef.current?.abort();
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  const family = activeTab === "cs" ? analysis.cs : analysis.vshell;
  const baseline = activeTab === "cs" ? CS_BASELINE : VSHELL_BASELINE;
  const familyLabel = activeTab === "cs" ? "CS / Cobalt Strike" : "VShell";

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
      <AnalysisHero
        icon={<Bug className="h-5 w-5" />}
        title="C2 样本分析"
        subtitle="C2 SAMPLE ANALYSIS"
        description="围绕 Cobalt Strike 与 VShell 先建立统一骨架，按公开流量画像预留 Beacon、Listener、WebSocket、DNS 与 APT 归因证据位。"
        tags={["Cobalt Strike", "VShell", "Beacon", "Tunnel"]}
        tagsLabel="样本域"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="rose" className="mb-3">正在加载 C2 样本分析骨架...</StatusHint>}

      {!loading && error && <StatusHint tone="amber" className="mb-3">{error}</StatusHint>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label="命中包" value={analysis.totalMatchedPackets.toLocaleString()} icon={<Shield className="h-4 w-4" />} tone="rose" />
        <MetricCard label="CS 候选" value={analysis.cs.candidateCount.toLocaleString()} icon={<Radio className="h-4 w-4" />} tone="blue" />
        <MetricCard label="VShell 候选" value={analysis.vshell.candidateCount.toLocaleString()} icon={<Server className="h-4 w-4" />} tone="cyan" />
        <MetricCard label="归因预留" value={String((analysis.cs.relatedActors?.length ?? 0) + (analysis.vshell.relatedActors?.length ?? 0))} icon={<Workflow className="h-4 w-4" />} tone="amber" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Family 分布">
          <AnalysisBucketChart data={analysis.families} emptyText="当前骨架未填充 CS / VShell 命中，后续规则会在这里汇总家族分布。" barClassName="bg-rose-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
        <C2Panel title="会话概览">
          <AnalysisList items={analysis.conversations.map((item) => ({ label: item.protocol ? `${item.protocol} · ${item.label}` : item.label, count: item.count }))} emptyText="当前骨架未填充 C2 会话，后续会聚合同 Host / URI / Channel 的候选通信。" />
        </C2Panel>
      </div>

      <div className="mt-4 rounded-[28px] border border-white/80 bg-white/90 p-2 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-2 md:grid-cols-2">
          <TabButton active={activeTab === "cs"} onClick={() => setActiveTab("cs")} icon={<Radio className="h-4 w-4" />} title="CS" description="HTTP/HTTPS、DNS、SMB Beacon 骨架" />
          <TabButton active={activeTab === "vshell"} onClick={() => setActiveTab("vshell")} icon={<Server className="h-4 w-4" />} title="VShell" description="TCP、WebSocket、DNS/DoH/DoT listener 骨架" />
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label={`${familyLabel} 候选`} value={family.candidateCount.toLocaleString()} />
        <MetricCard label="规则位" value={family.matchedRuleCount.toLocaleString()} />
        <MetricCard label="通道种类" value={String(family.channels.length)} />
        <MetricCard label="周期画像" value={String(family.beaconPatterns?.length ?? 0)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {baseline.map((item) => (
          <FeatureCard key={item.title} title={item.title} text={item.text} />
        ))}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Channel 分布`}>
          <AnalysisBucketChart data={family.channels} emptyText="尚未接入真实 channel 规则。" barClassName={activeTab === "cs" ? "bg-rose-500" : "bg-cyan-500"} labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
        <C2Panel title={`${familyLabel} 指标类型`}>
          <AnalysisBucketChart data={family.indicators} emptyText="尚未接入 indicator 统计。" barClassName="bg-indigo-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Beacon / Heartbeat 模式">
          <BeaconPatternList family={activeTab} patterns={family.beaconPatterns ?? []} />
        </C2Panel>
        <C2Panel title="APT 兼容扩展口">
          <div className="space-y-2">
            {SILVER_FOX_BASELINE.map((note, index) => (
              <div key={`${note}-${index}`} className="flex items-start gap-2 rounded-2xl border border-amber-100 bg-amber-50/70 px-3 py-2 text-xs leading-5 text-amber-800">
                <Workflow className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{note}</span>
              </div>
            ))}
          </div>
        </C2Panel>
      </div>

      {activeTab === "cs" && (
        <C2Panel title="CS Host / URI 聚合画像" className="mt-4">
          <CSHostURIAggregates items={analysis.cs.hostUriAggregates ?? []} />
        </C2Panel>
      )}

      {activeTab === "cs" && (
        <C2Panel title="CS DNS Beacon 聚合画像" className="mt-4">
          <CSDNSAggregates items={analysis.cs.dnsAggregates ?? []} />
        </C2Panel>
      )}

      {activeTab === "vshell" && (
        <C2Panel title="VShell Stream 聚合画像" className="mt-4">
          <VShellStreamAggregates items={analysis.vshell.streamAggregates ?? []} />
        </C2Panel>
      )}

      <C2Panel title={`${familyLabel} 候选证据表`} className="mt-4">
        <CandidateTable candidates={family.candidates} />
      </C2Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Notes`}>
          <NotesPanel notes={family.notes} emptyText="当前 family 仅完成骨架，下一轮规则接入后会输出强信号、中弱信号与样本特别说明。" />
        </C2Panel>
        <C2Panel title="全局 Notes">
          <NotesPanel notes={analysis.notes} emptyText="C2 分析骨架已就绪，当前抓包暂未生成全局说明。" />
        </C2Panel>
      </div>
    </PageShell>
  );
}

function C2Panel({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <SurfacePanel title={title} icon={<Network className="h-4 w-4 text-rose-600" />} className={className}>
      {children}
    </SurfacePanel>
  );
}

function TabButton({ active, onClick, icon, title, description }: { active: boolean; onClick: () => void; icon: ReactNode; title: string; description: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 rounded-[22px] border px-4 py-4 text-left transition-all",
        active
          ? "border-rose-200 bg-rose-50/90 text-rose-700 shadow-[0_18px_46px_-30px_rgba(225,29,72,0.55)]"
          : "border-transparent bg-transparent text-slate-500 hover:border-slate-200 hover:bg-white",
      )}
    >
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-current/20 bg-white/70">{icon}</span>
      <span>
        <span className="block text-sm font-semibold">{title}</span>
        <span className="mt-1 block text-xs leading-5 opacity-75">{description}</span>
      </span>
    </button>
  );
}

function FeatureCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-[24px] border border-rose-100 bg-[linear-gradient(135deg,rgba(255,241,242,0.86),rgba(255,255,255,0.96))] px-4 py-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <Activity className="h-4 w-4 text-rose-600" />
        {title}
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-600">{text}</p>
    </div>
  );
}

function BeaconPatternList({ family, patterns }: { family: C2Tab; patterns: NonNullable<C2FamilyAnalysis["beaconPatterns"]> }) {
  if (patterns.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-xs leading-6 text-slate-500">
        {family === "cs"
          ? "预留 CS sleep / jitter / DNS beacon / SMB pivot 行为画像位，当前尚未接入真实检测。"
          : "预留 VShell TCP 心跳、短长包交替、WebSocket 参数和 listener presence 画像位，当前尚未接入真实检测。"}
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {patterns.map((item) => (
        <div key={`${item.name}-${item.value}`} className="rounded-2xl border border-slate-100 bg-slate-50/70 px-3 py-2 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="font-semibold text-slate-800">{item.name}</span>
            <span className="font-mono text-slate-500">{item.value}</span>
          </div>
          <div className="mt-1 leading-5 text-slate-500">{item.summary}</div>
        </div>
      ))}
    </div>
  );
}

function CSHostURIAggregates({ items }: { items: C2HTTPEndpointAggregate[] }) {
  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 CS Host / URI 聚合。该区域会按 Host + URI 汇总 GET/POST、时间范围、平均间隔、jitter、stream 与 packet 列表，用于从单包候选升级到 Beacon 会话画像。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2HTTPEndpointAggregate>
      data={items}
      rowKey={(item, index) => `${item.host}-${item.uri}-${index}`}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName={C2_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1080px]"
      rowClassName={cn(C2_TABLE_ROW_CLASS, "hover:bg-rose-50/30")}
      columns={[
        {
          key: "endpoint",
          header: "Host / URI",
          widthClassName: "w-[30%]",
          cellClassName: "space-y-1",
          render: (item) => (
            <>
              <div className="break-all font-semibold text-slate-800">{item.host || "(no-host)"}</div>
              <div className="break-all font-mono text-[11px] text-slate-500">{item.uri || "(no-uri)"}</div>
              <TagLine values={[item.channel ?? "", item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
            </>
          ),
        },
        {
          key: "methods",
          header: "GET / POST",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>GET {item.getCount.toLocaleString()}</div>
              <div>POST {item.postCount.toLocaleString()}</div>
              <div className="mt-1 text-[10px] text-slate-400">Total {item.total.toLocaleString()}</div>
            </>
          ),
        },
        {
          key: "interval",
          header: "间隔 / Jitter",
          widthClassName: "w-36",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>{item.avgInterval || "--"}</div>
              <div className="text-[10px] text-slate-400">{item.jitter ? `jitter ${item.jitter}` : "jitter --"}</div>
              <IntervalSparkline values={item.intervals} color="stroke-rose-500" compact />
            </>
          ),
        },
        {
          key: "timeRange",
          header: "时间范围",
          widthClassName: "w-44",
          cellClassName: "space-y-1 font-mono text-[11px] text-slate-500",
          render: (item) => (
            <>
              <div>{item.firstTime || "--"}</div>
              <div>{item.lastTime || "--"}</div>
            </>
          ),
        },
        {
          key: "evidence",
          header: "Streams / Packets / 摘要 / 证据",
          cellClassName: "space-y-2",
          render: (item) => (
            <>
              <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
              {(item.scoreFactors ?? []).length > 0 && (
                <div className="rounded-2xl border border-rose-100 bg-rose-50/50 px-3 py-2">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-rose-400">Scoring Factors</div>
                  <div className="space-y-1">
                    {(item.scoreFactors ?? []).map((sf) => (
                      <div key={sf.name} className="flex items-start gap-2 text-[11px]">
                        <span
                          className={cn(
                            "mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full",
                            sf.direction === "positive" ? "bg-emerald-500" : "bg-amber-500",
                          )}
                        />
                        <div>
                          <span className="font-semibold text-slate-700">{sf.name}</span>
                          <span className="ml-1 text-slate-400">({sf.direction === "positive" ? "+" : ""}{sf.weight})</span>
                          {sf.summary && <div className="text-slate-500">{sf.summary}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {(item.signalTags ?? []).length > 0 && (
                <div className="rounded-2xl border border-slate-100 bg-slate-50/50 px-3 py-2">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Signal Tags</div>
                  <TagLine values={item.signalTags ?? []} />
                </div>
              )}
              <div className="grid gap-1 text-[11px] text-slate-500 md:grid-cols-2">
                <div className="break-all">
                  <span className="font-semibold text-slate-400">Streams </span>
                  {formatNumberList(item.streams)}
                </div>
                <div className="break-all">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
              </div>
              <TagLine values={(item.methods ?? []).map((method) => `${method.label}:${method.count}`)} />
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <EvidenceActions packetId={item.representativePacket || firstNumber(item.packets)} preferredProtocol="HTTP" />
                <FilterActions host={item.host === "(no-host)" ? "" : item.host} uri={item.uri === "(no-uri)" ? "" : item.uri} />
              </div>
            </>
          ),
        },
      ]}
    />
  );
}

function CSDNSAggregates({ items }: { items: C2DNSAggregate[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(() => new Set());

  const toggleExpanded = (rowKey: string) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(rowKey)) {
        next.delete(rowKey);
      } else {
        next.add(rowKey);
      }
      return next;
    });
  };

  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 CS DNS 聚合。该区域会按 qname 汇总 DNS 查询类型、TXT/NULL/CNAME 分布、请求/响应比例、时间间隔与 packet 列表，用于 DNS Beacon 画像。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2DNSAggregate>
      data={items}
      rowKey={(item, index) => `${item.qname}-${index}`}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName={C2_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1080px]"
      rowClassName={(item, index) => cn(C2_TABLE_ROW_CLASS, expandedRows.has(`${item.qname}-${index}`) ? "bg-rose-50/25" : "hover:bg-rose-50/30")}
      expandedRowClassName="border-rose-100/80 bg-rose-50/20"
      renderExpandedRow={(item, index) => expandedRows.has(`${item.qname}-${index}`) ? <CSDNSAggregateDetailPanel item={item} /> : null}
      columns={[
        {
          key: "qname",
          header: "QName",
          widthClassName: "w-[30%]",
          cellClassName: "space-y-1",
          render: (item) => (
            <>
              <div className="break-all font-mono font-semibold text-slate-800">{item.qname}</div>
              <div className="text-[10px] text-slate-400">max_label={item.maxLabelLength}</div>
              <TagLine values={[item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
            </>
          ),
        },
        {
          key: "queryTypes",
          header: "查询类型",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div className="space-y-0.5">
                {(item.queryTypes ?? []).map((qt) => (
                  <div key={qt.label}>{qt.label} {qt.count}</div>
                ))}
              </div>
              <div className="mt-1 text-[10px] text-slate-400">Total {item.total.toLocaleString()}</div>
            </>
          ),
        },
        {
          key: "dnsShape",
          header: "TXT/NULL/CNAME",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              {item.txtCount > 0 && <div>TXT {item.txtCount}</div>}
              {item.nullCount > 0 && <div>NULL {item.nullCount}</div>}
              {item.cnameCount > 0 && <div>CNAME {item.cnameCount}</div>}
              {item.txtCount === 0 && item.nullCount === 0 && item.cnameCount === 0 && <div className="text-slate-400">--</div>}
            </>
          ),
        },
        {
          key: "requestResponse",
          header: "请求/响应",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>req {item.requestCount}</div>
              <div>resp {item.responseCount}</div>
            </>
          ),
        },
        {
          key: "interval",
          header: "间隔 / Jitter",
          widthClassName: "w-36",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              <div>{item.avgInterval || "--"}</div>
              <div className="text-[10px] text-slate-400">{item.jitter ? `jitter ${item.jitter}` : "jitter --"}</div>
              <div className="mt-1 text-[10px] text-slate-400">{item.firstTime || "--"} ~ {item.lastTime || "--"}</div>
            </>
          ),
        },
        {
          key: "evidence",
          header: "摘要 / Packets / 证据",
          cellClassName: "space-y-2",
          render: (item, index) => {
            const rowKey = `${item.qname}-${index}`;
            const expanded = expandedRows.has(rowKey);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="break-all text-[11px] text-slate-500">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <AggregateExpandButton expanded={expanded} label={`DNS 聚合详情 ${item.qname}`} onClick={() => toggleExpanded(rowKey)} />
                  <EvidenceActions packetId={firstNumber(item.packets)} preferredProtocol="UDP" />
                  <FilterActions protocol="dns" qname={item.qname} dnsQueryType={item.txtCount > 0 ? "TXT" : undefined} />
                </div>
              </>
            );
          },
        },
      ]}
    />
  );
}

function VShellStreamAggregates({ items }: { items: C2StreamAggregate[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<number>>(() => new Set());

  const toggleExpanded = (streamId: number) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(streamId)) {
        next.delete(streamId);
      } else {
        next.add(streamId);
      }
      return next;
    });
  };

  if (items.length === 0) {
    return (
      <EmptyState className="text-left">
        尚未形成 VShell Stream 聚合。该区域会按 stream 汇总架构标记、长度前缀、短长包交替、心跳间隔与 WebSocket 参数，用于 VShell stream-level 画像。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2StreamAggregate>
      data={items}
      rowKey={(item) => item.streamId}
      maxHeightClassName="max-h-[360px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName="bg-gradient-to-r from-slate-100 to-cyan-50 text-slate-700"
      tableClassName="min-w-[1080px]"
      rowClassName={(item) => cn(C2_TABLE_ROW_CLASS, expandedRows.has(item.streamId) ? "bg-cyan-50/30" : "hover:bg-cyan-50/30")}
      expandedRowClassName="border-cyan-100/80 bg-cyan-50/20"
      renderExpandedRow={(item) => expandedRows.has(item.streamId) ? <VShellStreamAggregateDetailPanel item={item} /> : null}
      columns={[
        {
          key: "stream",
          header: "Stream",
          widthClassName: "w-20",
          render: (item) => (
            <>
              <div className="font-mono font-semibold text-slate-800">{item.streamId}</div>
              <div className="text-[10px] text-slate-400">{item.protocol || "tcp"}</div>
              <div className="text-[10px] text-slate-400">{item.totalPackets} 包</div>
              <TagLine values={[item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
            </>
          ),
        },
        {
          key: "arch",
          header: "架构标记",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (item.archMarkers ?? []).length > 0 ? (
            <div className="space-y-0.5">
              {item.archMarkers!.map((am) => (
                <div key={am.label}>{am.label} {am.count}</div>
              ))}
            </div>
          ) : (
            <div className="text-slate-400">--</div>
          ),
        },
        {
          key: "lengthPrefix",
          header: "长度前缀",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => item.lengthPrefixCount > 0 ? <div>{item.lengthPrefixCount} 次</div> : <div className="text-slate-400">--</div>,
        },
        {
          key: "packetShape",
          header: "短/长包",
          widthClassName: "w-28",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => item.shortPackets > 0 || item.longPackets > 0 ? (
            <div>
              <div>短 {item.shortPackets}</div>
              <div>长 {item.longPackets}</div>
              <div className="text-[10px] text-slate-400">transitions={item.transitions}</div>
            </div>
          ) : (
            <div className="text-slate-400">--</div>
          ),
        },
        {
          key: "heartbeat",
          header: "心跳",
          widthClassName: "w-36",
          cellClassName: C2_MONO_CELL_CLASS,
          render: (item) => (
            <>
              {item.heartbeatAvg ? (
                <div>
                  <div>{item.heartbeatAvg}</div>
                  <div className="text-[10px] text-slate-400">jitter {item.heartbeatJitter || "--"}</div>
                </div>
              ) : (
                <div className="text-slate-400">--</div>
              )}
              {item.hasWebSocket && <div className="mt-1 text-[10px] text-cyan-600">WebSocket</div>}
            </>
          ),
        },
        {
          key: "evidence",
          header: "摘要 / Packets / 证据",
          cellClassName: "space-y-2",
          render: (item) => {
            const expanded = expandedRows.has(item.streamId);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="break-all text-[11px] text-slate-500">
                  <span className="font-semibold text-slate-400">Packets </span>
                  {formatNumberList(item.packets)}
                </div>
                {(item.listenerHints ?? []).length > 0 && <TagLine values={item.listenerHints!.map((h) => `${h.label}:${h.count}`)} />}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <AggregateExpandButton expanded={expanded} label={`VShell Stream 聚合详情 ${item.streamId}`} onClick={() => toggleExpanded(item.streamId)} />
                  <EvidenceActions packetId={firstNumber(item.packets)} preferredProtocol="TCP" />
                  <FilterActions protocol="tcp" streamId={item.streamId} />
                </div>
              </>
            );
          },
        },
      ]}
    />
  );
}

function CandidateTable({ candidates }: { candidates: C2IndicatorRecord[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(() => new Set());

  const toggleExpanded = (rowKey: string) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(rowKey)) {
        next.delete(rowKey);
      } else {
        next.add(rowKey);
      }
      return next;
    });
  };

  if (candidates.length === 0) {
    return (
      <EmptyState className="py-8">
        当前仅完成候选证据表骨架。后续规则会填充 family、channel、indicator、confidence、actorHints 与 tags；命中后可直接定位包或打开关联流。
      </EmptyState>
    );
  }
  return (
    <DataTable<C2IndicatorRecord>
      data={candidates}
      rowKey={(item, index) => candidateRowKey(item, index)}
      maxHeightClassName="max-h-[440px]"
      wrapperClassName={C2_TABLE_WRAPPER_CLASS}
      headerClassName={C2_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1120px]"
      rowClassName={(item, index) => cn(C2_TABLE_ROW_CLASS, expandedRows.has(candidateRowKey(item, index)) ? "bg-rose-50/25" : "hover:bg-slate-50/70")}
      expandedRowClassName="border-rose-100/80 bg-rose-50/20"
      renderExpandedRow={(item, index) => {
        const tags = candidateTagValues(item);
        return expandedRows.has(candidateRowKey(item, index)) ? <CandidateDetailPanel item={item} tags={tags} /> : null;
      }}
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-16", cellClassName: "font-mono text-slate-500", render: (item) => item.packetId || "--" },
        { key: "family", header: "Family", widthClassName: "w-20", cellClassName: "font-semibold text-slate-800", render: (item) => item.family },
        { key: "channel", header: "Channel", widthClassName: "w-24", render: (item) => item.channel || "--" },
        { key: "type", header: "类型", widthClassName: "w-32", render: (item) => item.indicatorType || "--" },
        { key: "value", header: "值", widthClassName: "w-44", cellClassName: "break-all font-mono text-[11px] text-slate-600", render: (item) => item.indicatorValue || item.uri || item.host || "--" },
        { key: "confidence", header: "置信度", widthClassName: "w-20", cellClassName: C2_MONO_CELL_CLASS, render: (item) => item.confidence ?? "--" },
        {
          key: "summary",
          header: "摘要 / 标签",
          cellClassName: "space-y-2",
          render: (item, index) => {
            const rowKey = candidateRowKey(item, index);
            const expanded = expandedRows.has(rowKey);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    aria-label={`${expanded ? "收起" : "展开"} C2 候选详情 #${item.packetId || index + 1}`}
                    onClick={() => toggleExpanded(rowKey)}
                    className={cn(
                      "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold transition-all duration-200",
                      expanded
                        ? "border-rose-200 bg-rose-50 text-rose-700 shadow-[0_12px_28px_-22px_rgba(225,29,72,0.75)]"
                        : "border-slate-200 bg-white text-slate-600 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700",
                    )}
                  >
                    {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    {expanded ? "收起详情" : "展开详情"}
                  </button>
                  <TagLine values={compactCandidateTags(candidateTagValues(item))} />
                </div>
              </>
            );
          },
        },
        {
          key: "actions",
          header: "证据联动",
          widthClassName: "w-44",
          render: (item) => (
            <div className="flex flex-col items-start gap-2">
              <EvidenceActions packetId={item.packetId} preferredProtocol={preferredProtocolForCandidate(item)} className="flex-col items-start" />
              <CandidateFilterActions item={item} />
            </div>
          ),
        },
      ]}
    />
  );
}

function formatNumberList(values?: number[]) {
  if (!values || values.length === 0) return "--";
  return values.slice(0, 10).join(", ") + (values.length > 10 ? `, +${values.length - 10}` : "");
}

function firstNumber(values?: number[]) {
  const value = values?.find((item) => Number.isFinite(item) && item > 0);
  return value ?? 0;
}

function candidateRowKey(item: C2IndicatorRecord, index: number) {
  return `${item.family}-${item.packetId}-${item.streamId ?? "no-stream"}-${index}`;
}

function IntervalSparkline({ values, color = "stroke-rose-500", compact = false }: { values?: number[]; color?: string; compact?: boolean }) {
  const cleanValues = (values ?? []).filter((value) => Number.isFinite(value) && value > 0);
  if (cleanValues.length < 2) return null;
  const preview = cleanValues.slice(0, 6).map((value) => `${value.toFixed(value >= 10 ? 0 : 1)}s`).join(" / ");
  return (
    <div className={cn(
      "rounded-2xl border border-slate-100 bg-white/80 px-3 py-2",
      compact ? "mt-2 px-2 py-1" : "mt-3",
    )}>
      <div className="mb-1 flex items-center justify-between gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-400">
        <span>Interval Sparkline</span>
        <span className="font-mono normal-case tracking-normal text-slate-500">{preview}{cleanValues.length > 6 ? " ..." : ""}</span>
      </div>
      <Sparkline values={cleanValues} color={color} width={compact ? 96 : 180} height={compact ? 20 : 28} />
    </div>
  );
}

function AggregateExpandButton({ expanded, label, onClick }: { expanded: boolean; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-label={`${expanded ? "收起" : "展开"} ${label}`}
      onClick={onClick}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold transition-all duration-200",
        expanded
          ? "border-violet-200 bg-violet-50 text-violet-700 shadow-[0_12px_28px_-22px_rgba(124,58,237,0.75)]"
          : "border-slate-200 bg-white text-slate-600 hover:border-violet-200 hover:bg-violet-50 hover:text-violet-700",
      )}
    >
      {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
      {expanded ? "收起详情" : "展开详情"}
    </button>
  );
}

function CSDNSAggregateDetailPanel({ item }: { item: C2DNSAggregate }) {
  const metrics = [
    { label: "QName", value: item.qname },
    { label: "时间范围", value: item.firstTime || item.lastTime ? `${item.firstTime || "--"} ~ ${item.lastTime || "--"}` : "" },
    { label: "平均间隔", value: item.avgInterval },
    { label: "Jitter", value: item.jitter },
    { label: "最大 Label", value: item.maxLabelLength ? String(item.maxLabelLength) : "" },
    { label: "请求/响应", value: `${item.requestCount} / ${item.responseCount}` },
    { label: "Packet 时间序列", value: formatNumberList(item.packets) },
  ];
  const queryTypeTags = (item.queryTypes ?? []).map((qt) => `${qt.label}:${qt.count}`);
  const dnsShapeTags = [
    item.txtCount > 0 ? `TXT:${item.txtCount}` : "",
    item.nullCount > 0 ? `NULL:${item.nullCount}` : "",
    item.cnameCount > 0 ? `CNAME:${item.cnameCount}` : "",
  ].filter(Boolean);

  return (
    <div className="overflow-hidden rounded-[24px] border border-rose-100 bg-white/95 p-4 shadow-[0_20px_60px_-48px_rgba(15,23,42,0.55)] transition-all duration-200">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">DNS Aggregate Detail</div>
          <div className="mt-1 break-all font-mono text-xs text-slate-700">{item.summary || item.qname}</div>
        </div>
        <TagLine values={["dns-beacon-review", item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
      </div>
      <DetailMetricGrid rows={metrics} />
      <IntervalSparkline values={item.intervals} color="stroke-rose-500" />
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-3">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">Query Type 分布</div>
          <TagLine values={queryTypeTags.length > 0 ? queryTypeTags : ["--"]} />
        </div>
        <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-3">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">TXT / NULL / CNAME 形态</div>
          <TagLine values={dnsShapeTags.length > 0 ? dnsShapeTags : ["no-txt-null-cname"]} />
        </div>
      </div>
    </div>
  );
}

function VShellStreamAggregateDetailPanel({ item }: { item: C2StreamAggregate }) {
  const metrics = [
    { label: "Stream", value: String(item.streamId) },
    { label: "协议", value: item.protocol || "TCP" },
    { label: "总包数", value: String(item.totalPackets) },
    { label: "长度前缀", value: item.lengthPrefixCount > 0 ? `${item.lengthPrefixCount} 次` : "" },
    { label: "短/长包", value: `${item.shortPackets} / ${item.longPackets}` },
    { label: "状态转移", value: typeof item.transitions === "number" ? String(item.transitions) : "" },
    { label: "心跳", value: item.heartbeatAvg ? `${item.heartbeatAvg} · jitter ${item.heartbeatJitter || "--"}` : "" },
    { label: "Packet 时间序列", value: formatNumberList(item.packets) },
  ];
  const archTags = (item.archMarkers ?? []).map((marker) => `${marker.label}:${marker.count}`);
  const listenerTags = (item.listenerHints ?? []).map((hint) => `${hint.label}:${hint.count}`);

  return (
    <div className="overflow-hidden rounded-[24px] border border-cyan-100 bg-white/95 p-4 shadow-[0_20px_60px_-48px_rgba(15,23,42,0.55)] transition-all duration-200">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">VShell Stream Detail</div>
          <div className="mt-1 break-all font-mono text-xs text-slate-700">{item.summary || `tcp.stream == ${item.streamId}`}</div>
        </div>
        <TagLine values={["stream-level-review", item.hasWebSocket ? "websocket" : "", item.confidence ? `confidence:${item.confidence}` : ""].filter(Boolean)} />
      </div>
      <DetailMetricGrid rows={metrics} />
      <IntervalSparkline values={item.intervals} color="stroke-cyan-500" />
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-3">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">架构标记 / Payload 形态</div>
          <TagLine values={archTags.length > 0 ? archTags : ["no-arch-marker"]} />
        </div>
        <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-3">
          <div className="mb-2 text-[11px] font-semibold text-slate-400">Listener / 管理面提示</div>
          <TagLine values={listenerTags.length > 0 ? listenerTags : ["no-listener-hint"]} />
        </div>
      </div>
    </div>
  );
}

function DetailMetricGrid({ rows }: { rows: Array<{ label: string; value?: string }> }) {
  const visibleRows = rows.filter((row) => row.value && row.value.trim() !== "");
  if (visibleRows.length === 0) return null;
  return (
    <div className="grid gap-1.5 rounded-2xl border border-slate-100 bg-slate-50/70 p-2 md:grid-cols-2">
      {visibleRows.map((row) => (
        <div key={row.label} className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-2 text-[11px] leading-5">
          <span className="font-semibold text-slate-400">{row.label}</span>
          <span className="break-all font-mono text-slate-600">{row.value}</span>
        </div>
      ))}
    </div>
  );
}

function CandidateFilterActions({ item }: { item: C2IndicatorRecord }) {
  const channel = (item.channel ?? "").toLowerCase();
  const indicatorType = (item.indicatorType ?? "").toLowerCase();
  const indicatorValue = item.indicatorValue?.trim() ?? "";
  const isDns = channel === "dns" || indicatorType.includes("dns");
  const isTcpLike = channel === "tcp" || channel === "smb" || channel === "dot" || item.family === "vshell";

  if (isDns) {
    const qname = item.host || indicatorValue;
    return qname ? <FilterActions protocol="dns" qname={qname} dnsQueryType={indicatorValue.toUpperCase().includes("TXT") ? "TXT" : undefined} /> : null;
  }
  if (isTcpLike && typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  if (item.host || item.uri) {
    return <FilterActions protocol="http" host={item.host} uri={item.uri} />;
  }
  if (typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  return null;
}

function CandidateDetailPanel({ item, tags }: { item: C2IndicatorRecord; tags: string[] }) {
  return (
    <div className="overflow-hidden rounded-[24px] border border-rose-100 bg-white/95 p-4 shadow-[0_20px_60px_-48px_rgba(15,23,42,0.55)] transition-all duration-200">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Evidence Context</div>
          <CandidateContext item={item} />
          <div className="mt-3">
            <TagLine values={tags} />
          </div>
        </div>
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Typed Record Preview</div>
          <pre className="max-h-60 overflow-auto rounded-2xl border border-slate-100 bg-slate-950 p-3 text-[11px] leading-5 text-slate-100">
            {JSON.stringify(candidatePreviewRecord(item), null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

function CandidateContext({ item }: { item: C2IndicatorRecord }) {
  const endpoint = item.source || item.destination ? `${item.source || "?"} → ${item.destination || "?"}` : "";
  const rows = [
    { label: "时间", value: item.time },
    { label: "Stream", value: typeof item.streamId === "number" ? String(item.streamId) : "" },
    { label: "端点", value: endpoint },
    { label: "Host", value: item.host },
    { label: "URI", value: item.uri },
    { label: "Method", value: item.method },
    { label: "Evidence", value: item.evidence },
  ].filter((row) => row.value && String(row.value).trim() !== "");

  if (rows.length === 0) return null;

  return (
    <div className="mt-2 grid gap-1.5 rounded-2xl border border-slate-100 bg-slate-50/70 p-2">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2 text-[11px] leading-5">
          <span className="font-semibold text-slate-400">{row.label}</span>
          <span className="break-all font-mono text-slate-600">{row.value}</span>
        </div>
      ))}
    </div>
  );
}

function candidateTagValues(item: C2IndicatorRecord) {
  return uniqueValues([
    ...(item.tags ?? []),
    ...(item.actorHints ?? []),
    item.sampleFamily ?? "",
    item.campaignStage ?? "",
    ...(item.transportTraits ?? []),
    ...(item.infrastructureHints ?? []),
    ...(item.ttpTags ?? []),
  ]);
}

function compactCandidateTags(tags: string[]) {
  if (tags.length <= 5) return tags;
  return [...tags.slice(0, 5), `+${tags.length - 5} more`];
}

function uniqueValues(values: string[]) {
  const seen = new Set<string>();
  const next: string[] = [];
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    next.push(normalized);
  }
  return next;
}

function candidatePreviewRecord(item: C2IndicatorRecord) {
  return {
    packetId: item.packetId,
    streamId: item.streamId,
    time: item.time,
    family: item.family,
    channel: item.channel,
    source: item.source,
    destination: item.destination,
    host: item.host,
    uri: item.uri,
    method: item.method,
    indicatorType: item.indicatorType,
    indicatorValue: item.indicatorValue,
    confidence: item.confidence,
    evidence: item.evidence,
    actorHints: item.actorHints,
    sampleFamily: item.sampleFamily,
    campaignStage: item.campaignStage,
    transportTraits: item.transportTraits,
    infrastructureHints: item.infrastructureHints,
    ttpTags: item.ttpTags,
  };
}

function preferredProtocolForCandidate(item: C2IndicatorRecord): "HTTP" | "TCP" | "UDP" | undefined {
  const channel = (item.channel ?? "").toLowerCase();
  if (item.method || channel === "http" || channel === "websocket" || channel === "doh") {
    return "HTTP";
  }
  if (channel === "dns" || channel === "kcp_udp" || channel === "udp") {
    return "UDP";
  }
  if (channel === "tcp" || channel === "smb" || channel === "dot") {
    return "TCP";
  }
  return undefined;
}

function TagLine({ values }: { values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold text-slate-500">
          {value}
        </span>
      ))}
    </div>
  );
}

function NotesPanel({ notes, emptyText }: { notes: string[]; emptyText: string }) {
  if (notes.length === 0) {
    return <EmptyState className="text-left">{emptyText}</EmptyState>;
  }
  return (
    <div className="space-y-2">
      {notes.map((note, index) => (
        <div key={`${note}-${index}`} className="flex items-start gap-2 rounded-2xl border border-slate-100 bg-slate-50/70 px-3 py-2 text-xs leading-5 text-slate-600">
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

export function buildC2SampleAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  if (!filePath.trim()) return "";
  return `${captureRevision}::${filePath}::${totalPackets}`;
}
