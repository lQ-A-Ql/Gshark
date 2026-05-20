import { KeyRound } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ShiroRememberMeAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { InvestigationReportPanel } from "../../components/InvestigationReportPanel";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, NotesList } from "../ui";
import { ShiroRememberMeCandidateList } from "./ShiroRememberMeCandidateList";
import { ShiroRememberMeControls } from "./ShiroRememberMeControls";
import { ShiroRememberMeKeyResultsPanel } from "./ShiroRememberMeKeyResultsPanel";
import {
  filterShiroCandidates,
  parseShiroCustomKeyLines,
  renderShiroAnalysisText,
  selectShiroCandidate,
  shouldPreserveShiroSelection,
  type ShiroRememberMeCandidateFilter,
} from "./ShiroRememberMeUtils";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { MiscModuleSurface } from "./MiscModuleSurface";

const EMPTY_ANALYSIS: ShiroRememberMeAnalysis = {
  candidateCount: 0,
  hitCount: 0,
  candidates: [],
  notes: [],
  report: EMPTY_INVESTIGATION_REPORT,
};

export function ShiroRememberMeAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<ShiroRememberMeAnalysis>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [candidateFilter, setCandidateFilter] = useState<ShiroRememberMeCandidateFilter>("ALL");
  const [customKeys, setCustomKeys] = useState("");
  const [selectedPacketId, setSelectedPacketId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const keyLines = useMemo(() => parseShiroCustomKeyLines(customKeys), [customKeys]);

  const loadAnalysis = useCallback(
    (keys: string[], preserveSelection = true) => {
      if (!hasCapture) {
        cancelAnalysisRequest();
        setAnalysis(EMPTY_ANALYSIS);
        setSelectedPacketId(0);
        setError("");
        setLoading(false);
        return;
      }
      setLoading(true);
      setError("");
      return runAnalysisRequest({
        request: (signal) => backendClients.analysis.getShiroRememberMeAnalysis(keys, signal),
        onSuccess: (payload) => {
          setAnalysis(payload);
          setSelectedPacketId((current) =>
            preserveSelection && shouldPreserveShiroSelection(payload.candidates, current)
              ? current
              : (payload.candidates[0]?.packetId ?? 0),
          );
        },
        onError: (err) => {
          setAnalysis(EMPTY_ANALYSIS);
          setSelectedPacketId(0);
          setError(err instanceof Error ? err.message : "加载 Shiro rememberMe 分析失败");
        },
        onSettled: () => setLoading(false),
      });
    },
    [cancelAnalysisRequest, hasCapture, runAnalysisRequest],
  );

  useEffect(() => loadAnalysis([], false), [fileMeta.path, loadAnalysis]);

  const filteredCandidates = useMemo(
    () => filterShiroCandidates(analysis.candidates, candidateFilter),
    [analysis.candidates, candidateFilter],
  );

  const selectedCandidate = useMemo(
    () => selectShiroCandidate(filteredCandidates, selectedPacketId),
    [filteredCandidates, selectedPacketId],
  );

  function exportAnalysis(format: MiscExportFormat) {
    exportStructuredResult({
      filenameBase: "shiro-rememberme-analysis",
      format,
      payload: analysis,
      renderText: renderShiroAnalysisText,
    });
  }

  return (
    <MiscModuleSurface module={module} embedded={embedded} icon={<KeyRound className="h-4 w-4" />} tone="amber">
      <ShiroRememberMeControls
        candidateCount={analysis.candidateCount}
        candidateFilter={candidateFilter}
        captureName={fileMeta.name}
        customKeyCount={keyLines.length}
        customKeys={customKeys}
        hasCapture={hasCapture}
        hitCount={analysis.hitCount}
        loading={loading}
        module={module}
        onCandidateFilterChange={setCandidateFilter}
        onCustomKeysChange={setCustomKeys}
        onExport={exportAnalysis}
        onRefresh={() => void loadAnalysis(keyLines, true)}
      />

      {!error && <NotesList notes={analysis.notes} />}
      {error && <ErrorBlock message={error} />}
      <InvestigationReportPanel report={analysis.report} preferredProtocol="HTTP" />

      <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.95fr)_minmax(0,1.05fr)]">
        <ShiroRememberMeCandidateList
          candidates={filteredCandidates}
          hasCapture={hasCapture}
          onSelectCandidate={setSelectedPacketId}
          selectedCandidate={selectedCandidate}
        />
        <ShiroRememberMeKeyResultsPanel selectedCandidate={selectedCandidate} />
      </div>
    </MiscModuleSurface>
  );
}
