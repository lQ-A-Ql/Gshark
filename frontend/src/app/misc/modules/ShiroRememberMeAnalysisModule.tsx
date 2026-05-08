import { KeyRound } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ShiroRememberMeAnalysis } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
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

const EMPTY_ANALYSIS: ShiroRememberMeAnalysis = {
  candidateCount: 0,
  hitCount: 0,
  candidates: [],
  notes: [],
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
        request: (signal) => bridge.getShiroRememberMeAnalysis(keys, signal),
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
    <Card
      className={
        embedded
          ? "min-w-0 h-fit border-0 bg-transparent shadow-none"
          : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"
      }
    >
      <CardHeader className={embedded ? "hidden" : "gap-2 border-b border-slate-100 bg-slate-50/70 pb-5"}>
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-100 text-amber-700">
            <KeyRound className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
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

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.95fr)_minmax(0,1.05fr)]">
          <ShiroRememberMeCandidateList
            candidates={filteredCandidates}
            hasCapture={hasCapture}
            onSelectCandidate={setSelectedPacketId}
            selectedCandidate={selectedCandidate}
          />
          <ShiroRememberMeKeyResultsPanel selectedCandidate={selectedCandidate} />
        </div>
      </CardContent>
    </Card>
  );
}
