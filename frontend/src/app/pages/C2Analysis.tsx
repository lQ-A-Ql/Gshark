import { Bug, Radio, Server, Shield, Workflow } from "lucide-react";
import { useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { MetricCard, StatusHint } from "../components/DesignSystem";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { AnalysisBucketChart, AnalysisList } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { CSDNSAggregates, CSHostURIAggregates, VShellStreamAggregates } from "../features/c2/C2AggregateTables";
import { C2BeaconPatternList } from "../features/c2/C2BeaconPatternList";
import { C2CandidateTable } from "../features/c2/C2CandidateTable";
import { C2DecryptWorkbench } from "../features/c2/C2DecryptWorkbench";
import type { C2Tab } from "../features/c2/C2DecryptWorkbench";
import {
  C2AptHandoffNotes,
  C2FeatureCard,
  C2FamilyTabButton,
  C2NotesPanel,
  C2Panel,
  VShellEvidenceSummaryGrid,
} from "../features/c2/C2DisplayComponents";
import {
  C2_APT_HANDOFF_NOTES,
  CS_EVIDENCE_CARDS,
  VSHELL_EVIDENCE_CARDS,
  buildVShellEvidenceSummary,
} from "../features/c2/c2EvidenceModel";
import { useC2Analysis } from "../features/c2/useC2Analysis";
import { useSentinel } from "../state/SentinelContext";

export default function C2Analysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [activeTab, setActiveTab] = useState<C2Tab>("cs");
  const { analysis, loading, error, refreshAnalysis } = useC2Analysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const vshellEvidenceSummary = useMemo(() => buildVShellEvidenceSummary(analysis.vshell), [analysis.vshell]);

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  const family = activeTab === "cs" ? analysis.cs : analysis.vshell;
  const baseline = activeTab === "cs" ? CS_EVIDENCE_CARDS : VSHELL_EVIDENCE_CARDS;
  const familyLabel = activeTab === "cs" ? "CS / Cobalt Strike" : "VShell";
  const hasVShellCandidateEvidence = (analysis.vshell.candidates?.length ?? 0) > 0;

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
      <AnalysisHero
        icon={<Bug className="h-5 w-5" />}
        title="C2 样本分析"
        subtitle="C2 SAMPLE ANALYSIS"
        description="围绕 Cobalt Strike 与 VShell 汇总 Beacon、Listener、WebSocket、DNS、stream 聚合和 APT 归因线索；弱信号只作为复核提示，不直接包装成强结论。"
        tags={["Cobalt Strike", "VShell", "Beacon", "Tunnel"]}
        tagsLabel="样本域"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <StatusHint tone="rose" className="mb-3">
          正在加载 C2 样本分析...
        </StatusHint>
      )}

      {!loading && error && (
        <StatusHint tone="amber" className="mb-3">
          {error}
        </StatusHint>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard
          label="命中包"
          value={analysis.totalMatchedPackets.toLocaleString()}
          icon={<Shield className="h-4 w-4" />}
          tone="rose"
        />
        <MetricCard
          label="CS 候选"
          value={analysis.cs.candidateCount.toLocaleString()}
          icon={<Radio className="h-4 w-4" />}
          tone="blue"
        />
        <MetricCard
          label="VShell 候选"
          value={analysis.vshell.candidateCount.toLocaleString()}
          icon={<Server className="h-4 w-4" />}
          tone="cyan"
        />
        <MetricCard
          label="归因线索"
          value={String((analysis.cs.relatedActors?.length ?? 0) + (analysis.vshell.relatedActors?.length ?? 0))}
          icon={<Workflow className="h-4 w-4" />}
          tone="amber"
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Family 分布">
          <AnalysisBucketChart
            data={analysis.families}
            emptyText="当前抓包未形成 CS / VShell 命中，家族分布会在出现可复核候选后汇总。"
            barClassName="bg-rose-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </C2Panel>
        <C2Panel title="会话概览">
          <AnalysisList
            items={analysis.conversations.map((item) => ({
              label: item.protocol ? `${item.protocol} · ${item.label}` : item.label,
              count: item.count,
            }))}
            emptyText="当前抓包未形成 C2 会话聚合；命中后会按 Host / URI / Channel / stream 归并候选通信。"
          />
        </C2Panel>
      </div>

      <div className="mt-4 rounded-[28px] border border-white/80 bg-white/90 p-2 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-2 md:grid-cols-2">
          <C2FamilyTabButton
            active={activeTab === "cs"}
            onClick={() => setActiveTab("cs")}
            icon={<Radio className="h-4 w-4" />}
            title="CS"
            description="HTTP/HTTPS、DNS、SMB Beacon 证据聚合"
          />
          <C2FamilyTabButton
            active={activeTab === "vshell"}
            onClick={() => setActiveTab("vshell")}
            icon={<Server className="h-4 w-4" />}
            title="VShell"
            description="TCP、WebSocket、DNS/DoH/DoT listener 证据聚合"
          />
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
          <C2FeatureCard key={item.title} title={item.title} text={item.text} />
        ))}
      </div>
      <InvestigationReportPanel
        className="mt-4"
        preferredProtocol="HTTP"
        report={family.report}
        title={`${familyLabel} 调查报告`}
      />

      {activeTab === "vshell" && (
        <>
          {hasVShellCandidateEvidence ? (
            <StatusHint tone="cyan" className="mt-4">
              已形成 VShell candidates 候选证据；摘要卡片会并列融合 stream 聚合与候选弱信号，短长包、心跳、listener hint
              仍需结合候选证据表人工复核。
            </StatusHint>
          ) : null}
          <VShellEvidenceSummaryGrid items={vshellEvidenceSummary} />
        </>
      )}

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Channel 分布`}>
          <AnalysisBucketChart
            data={family.channels}
            emptyText="当前抓包未形成可复核 channel 命中。"
            barClassName={activeTab === "cs" ? "bg-rose-500" : "bg-cyan-500"}
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </C2Panel>
        <C2Panel title={`${familyLabel} 指标类型`}>
          <AnalysisBucketChart
            data={family.indicators}
            emptyText="当前抓包未形成 indicator 统计；低置信观察会保留在候选证据表中复核。"
            barClassName="bg-indigo-500"
            labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]"
          />
        </C2Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Beacon / Heartbeat 模式">
          <C2BeaconPatternList family={activeTab} patterns={family.beaconPatterns ?? []} />
        </C2Panel>
        <C2Panel title="APT 兼容扩展口">
          <C2AptHandoffNotes notes={C2_APT_HANDOFF_NOTES} />
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

      <C2Panel title="流量解密工作台" className="mt-4">
        <C2DecryptWorkbench family={activeTab} familyAnalysis={family} captureRevision={captureRevision} />
      </C2Panel>

      <C2Panel title={`${familyLabel} 候选证据表`} className="mt-4">
        <C2CandidateTable candidates={family.candidates} />
      </C2Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Notes`}>
          <C2NotesPanel
            notes={family.notes}
            emptyText="当前 family 暂无补充说明；命中后会输出强信号、中弱信号与样本特别说明。"
          />
        </C2Panel>
        <C2Panel title="全局 Notes">
          <C2NotesPanel notes={analysis.notes} emptyText="当前抓包暂未生成全局说明。" />
        </C2Panel>
      </div>
    </PageShell>
  );
}
