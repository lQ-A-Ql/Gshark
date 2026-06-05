import { useMemo, useState } from "react";
import { AlertTriangle, FileSearch, Network, Shield } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { MetricCard, SurfacePanel } from "../components/DesignSystem";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import {
  EvidenceCaveats,
  EvidenceDetailEmptyNotice,
  EvidenceDetailPanel,
  EvidenceFacetSidebar,
  EvidenceSeveritySummary,
  EvidenceStatusMessage,
  EvidenceTable,
  EvidenceToolbar,
} from "../features/evidence/EvidencePanelSections";
import type { EvidenceSeverity } from "../core/evidenceTypes";
import { useEvidencePanelModel } from "../features/evidence/useEvidencePanelModel";
import { useEvidence } from "../features/evidence/useEvidence";
import type { EvidenceFacetState } from "../features/evidence/evidencePanelRules";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";

function createEmptyFacets(): EvidenceFacetState {
  return {
    sourceTypes: [],
    features: [],
    entities: [],
    confidenceLabels: [],
  };
}

export default function EvidencePanel() {
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { totalPackets } = usePacket();
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<EvidenceSeverity | "all">("all");
  const [facets, setFacets] = useState<EvidenceFacetState>(createEmptyFacets);
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  const { evidence, loading, error, refreshEvidence } = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: selectedModules.length > 0 ? selectedModules : undefined,
  });

  const { sorted, severityCounts, report, facetGroups, summaryMetrics, selectedRecord, exportCSV, exportJSON } =
    useEvidencePanelModel(
      evidence,
      query,
      severityFilter,
      facets,
      selectedRecordId,
    );

  const toggleModule = (module: string) =>
    setSelectedModules((prev) => (prev.includes(module) ? prev.filter((item) => item !== module) : [...prev, module]));

  const toggleFacet = (group: keyof EvidenceFacetState, value: string) => {
    setFacets((prev) => ({
      ...prev,
      [group]: prev[group].includes(value) ? prev[group].filter((item) => item !== value) : [...prev[group], value],
    }));
  };

  const resetFacets = () => setFacets(createEmptyFacets());

  const heroTags = useMemo(
    () => ["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"],
    [],
  );

  return (
    <PageShell>
      <AnalysisHero
        icon={<Shield className="h-5 w-5" />}
        title="证据链总览"
        subtitle="UNIFIED EVIDENCE"
        description="将现有 Evidence 路由提升为调查中心: 左侧切面、中央高密度结果、右侧详情面板，并保留报告、导出与搜索能力。"
        tags={heroTags}
        tagsLabel="证据域"
        theme="indigo"
      />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="全部证据" value={summaryMetrics.totalRecords} hint={`当前显示 ${summaryMetrics.visibleRecords} 条`} icon={<FileSearch className="h-4 w-4" />} tone="indigo" />
        <MetricCard label="严重 / 高危" value={summaryMetrics.criticalHighCount} hint="优先建立调查链" icon={<AlertTriangle className="h-4 w-4" />} tone="rose" />
        <MetricCard label="原始包绑定" value={summaryMetrics.mappedPacketCount} hint="可直接回跳定位" icon={<Shield className="h-4 w-4" />} tone="blue" />
        <MetricCard label="关联流绑定" value={summaryMetrics.mappedStreamCount} hint={`${summaryMetrics.moduleCount} 个模块参与聚合`} icon={<Network className="h-4 w-4" />} tone="emerald" />
      </div>
      <SurfacePanel title="检索与快筛" description="现有搜索、模块筛选、严重级别和导出能力全部保留。" className="overflow-visible" bodyClassName="space-y-3">
        <EvidenceSeveritySummary
          counts={severityCounts}
          severityFilter={severityFilter}
          onSeverityFilterChange={setSeverityFilter}
        />
        <EvidenceToolbar
          evidenceCount={evidence.length}
          query={query}
          resultCount={sorted.length}
          selectedModules={selectedModules}
          onExportCSV={exportCSV}
          onExportJSON={exportJSON}
          onQueryChange={setQuery}
          onToggleModule={toggleModule}
        />
        <EvidenceStatusMessage error={error} loading={loading} onRetry={() => refreshEvidence(true)} />
      </SurfacePanel>
      <InvestigationReportPanel preferredProtocol="TCP" report={report} title="统一证据调查报告" />
      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1.25fr)_minmax(320px,0.9fr)]">
        <div className="min-w-0">
          <EvidenceFacetSidebar facets={facets} facetGroups={facetGroups} onToggleFacet={toggleFacet} onResetFacets={resetFacets} />
        </div>
        <SurfacePanel
          title={`证据结果 (${sorted.length})`}
          description="高密度列表支持选中单条证据，并在右侧查看结构化细节。"
          className="min-w-0"
          bodyClassName="space-y-3"
          actions={<span className="meow-diffuse-chip px-2 py-1 text-[10px] text-slate-500">Investigation Center</span>}
        >
          <EvidenceTable
            loading={loading}
            records={sorted}
            selectedId={selectedRecord?.id ?? null}
            onSelect={setSelectedRecordId}
          />
          <EvidenceCaveats records={sorted} />
        </SurfacePanel>
        <div className="min-w-0 space-y-3">
          <EvidenceDetailEmptyNotice />
          <EvidenceDetailPanel record={selectedRecord} />
        </div>
      </div>
    </PageShell>
  );
}
