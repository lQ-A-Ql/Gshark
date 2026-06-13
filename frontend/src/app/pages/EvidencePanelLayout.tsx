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
import type { EvidencePanelState } from "./useEvidencePanelState";

export function EvidencePanelLayout(state: EvidencePanelState) {
  return (
    <PageShell>
      <AnalysisHero
        icon={<Shield className="h-5 w-5" />}
        title="证据链总览"
        subtitle="UNIFIED EVIDENCE"
        description="将现有 Evidence 路由提升为调查中心: 左侧切面、中央高密度结果、右侧详情面板，并保留报告、导出与搜索能力。"
        tags={state.heroTags}
        tagsLabel="证据域"
        theme="indigo"
      />
      <EvidenceMetricCards state={state} />
      <EvidenceSearchPanel state={state} />
      <InvestigationReportPanel preferredProtocol="TCP" report={state.report} title="统一证据调查报告" />
      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1.25fr)_minmax(320px,0.9fr)]">
        <div className="min-w-0">
          <EvidenceFacetSidebar
            facets={state.facets}
            facetGroups={state.facetGroups}
            onToggleFacet={state.toggleFacet}
            onResetFacets={state.resetFacets}
          />
        </div>
        <EvidenceResultsPanel state={state} />
        <div className="min-w-0 space-y-3">
          <EvidenceDetailEmptyNotice />
          <EvidenceDetailPanel record={state.selectedRecord} />
        </div>
      </div>
    </PageShell>
  );
}

function EvidenceMetricCards({ state }: { state: EvidencePanelState }) {
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <MetricCard label="全部证据" value={state.summaryMetrics.totalRecords} hint={`当前显示 ${state.summaryMetrics.visibleRecords} 条`} icon={<FileSearch className="h-4 w-4" />} tone="indigo" />
      <MetricCard label="严重 / 高危" value={state.summaryMetrics.criticalHighCount} hint="优先建立调查链" icon={<AlertTriangle className="h-4 w-4" />} tone="rose" />
      <MetricCard label="原始包绑定" value={state.summaryMetrics.mappedPacketCount} hint="可直接回跳定位" icon={<Shield className="h-4 w-4" />} tone="blue" />
      <MetricCard label="关联流绑定" value={state.summaryMetrics.mappedStreamCount} hint={`${state.summaryMetrics.moduleCount} 个模块参与聚合`} icon={<Network className="h-4 w-4" />} tone="emerald" />
    </div>
  );
}

function EvidenceSearchPanel({ state }: { state: EvidencePanelState }) {
  return (
    <SurfacePanel title="检索与快筛" description="现有搜索、模块筛选、严重级别和导出能力全部保留。" className="overflow-visible" bodyClassName="space-y-3">
      <EvidenceSeveritySummary counts={state.severityCounts} severityFilter={state.severityFilter} onSeverityFilterChange={state.setSeverityFilter} />
      <EvidenceToolbar
        evidenceCount={state.evidence.length}
        query={state.query}
        resultCount={state.sorted.length}
        selectedModules={state.selectedModules}
        onExportCSV={state.exportCSV}
        onExportJSON={state.exportJSON}
        onQueryChange={state.setQuery}
        onToggleModule={state.toggleModule}
      />
      <EvidenceStatusMessage error={state.error} loading={state.loading} onRetry={() => state.refreshEvidence(true)} />
    </SurfacePanel>
  );
}

function EvidenceResultsPanel({ state }: { state: EvidencePanelState }) {
  return (
    <SurfacePanel title={`证据结果 (${state.sorted.length})`} description="高密度列表支持选中单条证据，并在右侧查看结构化细节。" className="min-w-0" bodyClassName="space-y-3" actions={<EvidenceResultsActions state={state} />}>
      <EvidenceTable loading={state.loading} records={state.visibleRecords} selectedId={state.selectedRecord?.id ?? null} onSelect={state.setSelectedRecordId} />
      {state.hasMoreVisibleRecords ? <ShowMoreEvidence state={state} /> : null}
      <EvidenceCaveats records={state.sorted} />
    </SurfacePanel>
  );
}

function EvidenceResultsActions({ state }: { state: EvidencePanelState }) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-2">
      {state.sorted.length > state.visibleRecords.length ? (
        <span className="meow-diffuse-chip px-2 py-1 text-[10px] text-slate-500">
          Showing {state.visibleRecords.length} of {state.sorted.length} evidence records
        </span>
      ) : null}
      <span className="meow-diffuse-chip px-2 py-1 text-[10px] text-slate-500">Investigation Center</span>
    </div>
  );
}

function ShowMoreEvidence({ state }: { state: EvidencePanelState }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="text-[11px] text-slate-500">
        已加载 {state.visibleRecords.length} / {state.sorted.length} 条筛选结果，点击继续显示后续 {Math.min(state.visibleLimit + 200, state.sorted.length) - state.visibleRecords.length} 条。
      </div>
      <button
        type="button"
        onClick={state.showNextVisibleRecords}
        className="meow-control-ghost rounded border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:border-indigo-200 hover:text-indigo-700"
      >
        Show next 200
      </button>
    </div>
  );
}
