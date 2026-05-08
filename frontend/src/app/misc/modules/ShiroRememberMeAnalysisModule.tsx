import { KeyRound } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ShiroRememberMeAnalysis, ShiroRememberMeCandidate } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, NotesList } from "../ui";
import { ShiroRememberMeCandidateList } from "./ShiroRememberMeCandidateList";
import { ShiroRememberMeControls, type ShiroRememberMeCandidateFilter } from "./ShiroRememberMeControls";
import { ShiroRememberMeKeyResultsPanel } from "./ShiroRememberMeKeyResultsPanel";

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

  const keyLines = useMemo(
    () =>
      customKeys
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    [customKeys],
  );

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
            preserveSelection && current && payload.candidates.some((item) => item.packetId === current)
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

  const filteredCandidates = useMemo(() => {
    return analysis.candidates.filter((item) => {
      if (candidateFilter === "HIT") return (item.hitCount ?? 0) > 0;
      if (candidateFilter === "DELETEME")
        return (item.notes ?? []).some((note) => note.toLowerCase().includes("deleteme"));
      return true;
    });
  }, [analysis.candidates, candidateFilter]);

  const selectedCandidate = useMemo(
    () => filteredCandidates.find((item) => item.packetId === selectedPacketId) ?? filteredCandidates[0] ?? null,
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

function renderCandidateTitle(item: ShiroRememberMeCandidate) {
  const location = item.host ? `${item.host}${item.path || "/"}` : item.path || "/";
  return `${item.cookieName || "rememberMe"} @ ${location}`;
}

function renderShiroAnalysisText(analysis: ShiroRememberMeAnalysis) {
  const lines = [
    "Shiro rememberMe 分析",
    `候选: ${analysis.candidateCount}`,
    `密钥命中: ${analysis.hitCount}`,
    "",
    "候选详情:",
  ];
  for (const candidate of analysis.candidates) {
    lines.push(`- #${candidate.packetId} ${renderCandidateTitle(candidate)}`);
    lines.push(
      `  来源: ${candidate.sourceHeader || "Cookie"} / stream=${candidate.streamId ?? "--"} / hit=${candidate.hitCount ?? 0}`,
    );
    if ((candidate.notes?.length ?? 0) > 0) {
      lines.push(`  备注: ${candidate.notes!.join("; ")}`);
    }
    for (const result of candidate.keyResults ?? []) {
      lines.push(
        `  Key ${result.label}: ${result.hit ? "HIT" : "MISS"} ${result.algorithm || ""} ${result.payloadClass || result.reason || ""}`.trim(),
      );
    }
  }
  return lines.join("\n");
}
