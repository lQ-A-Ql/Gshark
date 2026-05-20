import { useState } from "react";
import { Shield } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { AnalysisPanel } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import {
  EvidenceCaveats,
  EvidenceSeveritySummary,
  EvidenceStatusMessage,
  EvidenceTable,
  EvidenceToolbar,
} from "../features/evidence/EvidencePanelSections";
import type { EvidenceSeverity } from "../core/evidenceTypes";
import { useEvidencePanelModel } from "../features/evidence/useEvidencePanelModel";
import { useEvidence } from "../features/evidence/useEvidence";
import { useSentinel } from "../state/SentinelContext";

export default function EvidencePanel() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<EvidenceSeverity | "all">("all");

  const { evidence, loading, error } = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: selectedModules.length > 0 ? selectedModules : undefined,
  });

  const { sorted, severityCounts, report, exportCSV, exportJSON } = useEvidencePanelModel(
    evidence,
    query,
    severityFilter,
  );
  const toggleModule = (module: string) =>
    setSelectedModules((prev) => (prev.includes(module) ? prev.filter((item) => item !== module) : [...prev, module]));

  return (
    <PageShell>
      <AnalysisHero
        icon={<Shield className="h-5 w-5" />}
        title="证据链总览"
        subtitle="UNIFIED EVIDENCE"
        description="跨模块统一查看威胁狩猎、C2 分析、APT 画像、工控分析、车机分析、USB 分析和对象导出的证据记录，支持搜索、过滤和导出。"
        tags={["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"]}
        tagsLabel="证据域"
        theme="indigo"
      />
      <AnalysisPanel title="证据检索与筛选" tone="violet">
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
        <EvidenceStatusMessage error={error} loading={loading} />
      </AnalysisPanel>
      <InvestigationReportPanel preferredProtocol="TCP" report={report} title="统一证据调查报告" />
      <AnalysisPanel title={`证据记录 (${sorted.length})`} tone="violet">
        <EvidenceTable loading={loading} records={sorted} />
        <EvidenceCaveats records={sorted} />
      </AnalysisPanel>
    </PageShell>
  );
}
