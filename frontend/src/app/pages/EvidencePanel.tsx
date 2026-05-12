import { useState } from "react";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import {
  EvidenceCaveats,
  EvidenceHero,
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
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(99,102,241,0.26),transparent_36%),linear-gradient(180deg,#eef2ff_0%,#f5f3ff_44%,#f8fafc_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1200px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(99,102,241,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
        <EvidenceHero />
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
        <InvestigationReportPanel className="mb-6" preferredProtocol="TCP" report={report} title="统一证据调查报告" />
        <EvidenceTable loading={loading} records={sorted} />
        <EvidenceCaveats records={sorted} />
      </section>
    </PageShell>
  );
}
