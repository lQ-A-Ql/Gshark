import { KeyRound, RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import type { HTTPLoginAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { InvestigationReportPanel } from "../../components/InvestigationReportPanel";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { useMiscModuleAnalysis } from "../hooks/useMiscModuleAnalysis";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";
import { HTTPLoginDetailsPanel } from "./HTTPLoginDetailsPanel";
import { HTTPLoginEndpointList } from "./HTTPLoginEndpointList";
import {
  filterHTTPLoginAttemptsForEndpoint,
  filterHTTPLoginEndpoints,
  HTTP_LOGIN_RESULT_FILTERS,
  renderHTTPLoginAnalysisText,
  selectHTTPLoginEndpoint,
  type HTTPLoginResultFilter,
} from "./HTTPLoginAnalysisUtils";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";

const EMPTY_ANALYSIS: HTTPLoginAnalysis = {
  totalAttempts: 0,
  candidateEndpoints: 0,
  successCount: 0,
  failureCount: 0,
  uncertainCount: 0,
  bruteforceCount: 0,
  endpoints: [],
  attempts: [],
  notes: [],
  report: EMPTY_INVESTIGATION_REPORT,
};

export function HTTPLoginAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const fetchAnalysis = useCallback((signal: AbortSignal) => backendClients.analysis.getHTTPLoginAnalysis(signal), []);
  const { analysis, loading, error, refresh } = useMiscModuleAnalysis<HTTPLoginAnalysis>({
    fetch: fetchAnalysis,
    emptyData: EMPTY_ANALYSIS,
    errorMessage: "加载 HTTP 登录行为分析失败",
  });
  const [resultFilter, setResultFilter] = useState<HTTPLoginResultFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedEndpointKey, setSelectedEndpointKey] = useState("");
  const embedded = surfaceVariant === "embedded";

  const filteredEndpoints = useMemo(() => {
    return filterHTTPLoginEndpoints(analysis.endpoints, resultFilter, query);
  }, [analysis.endpoints, query, resultFilter]);

  const selectedEndpoint = useMemo(
    () => selectHTTPLoginEndpoint(filteredEndpoints, selectedEndpointKey),
    [filteredEndpoints, selectedEndpointKey],
  );

  const filteredAttempts = useMemo(() => {
    return filterHTTPLoginAttemptsForEndpoint(analysis.attempts, selectedEndpoint);
  }, [analysis.attempts, selectedEndpoint]);

  function exportAnalysis(format: MiscExportFormat) {
    exportStructuredResult({
      filenameBase: "http-login-analysis",
      format,
      payload: analysis,
      renderText: renderHTTPLoginAnalysisText,
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
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-100 text-cyan-600">
            <KeyRound className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
        <div className="flex flex-wrap gap-2 rounded-xl border border-cyan-100 bg-cyan-50/50 p-4 text-[11px] shadow-sm">
          <MetaChip label="抓包" value={hasCapture ? fileMeta.name : "未加载"} color={hasCapture ? "sky" : "slate"} />
          <MetaChip label="候选尝试" value={analysis.totalAttempts} color="slate" />
          <MetaChip label="端点" value={analysis.candidateEndpoints} color="slate" />
          <MetaChip label="成功" value={analysis.successCount} color="emerald" />
          <MetaChip label="失败" value={analysis.failureCount} color="rose" />
          <MetaChip label="待确认" value={analysis.uncertainCount} color="slate" />
          <MetaChip
            label="疑似爆破"
            value={analysis.bruteforceCount}
            color={analysis.bruteforceCount > 0 ? "rose" : "slate"}
          />
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="结果筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {HTTP_LOGIN_RESULT_FILTERS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setResultFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    resultFilter === item ? "bg-white text-cyan-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {item === "ALL" ? "全部" : item === "SUCCESS" ? "成功" : item === "FAILURE" ? "失败" : "待确认"}
                </button>
              ))}
            </div>
          </Field>
          <Field label="检索端点">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="登录路径 / Host / 参数键 / token / captcha"
              className="font-mono text-sm shadow-sm"
            />
          </Field>
          <div className="flex items-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => void refresh()}
              disabled={!hasCapture || loading}
              className="gap-2 bg-white text-cyan-700"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "分析中..." : "刷新"}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <ExportButtons disabled={analysis.totalAttempts === 0} onExport={exportAnalysis} />
        </div>

        {!error && <NotesList notes={analysis.notes} />}
        {error && <ErrorBlock message={error} />}
        <InvestigationReportPanel report={analysis.report} preferredProtocol="HTTP" />

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.92fr)_minmax(0,1.08fr)]">
          <HTTPLoginEndpointList
            hasCapture={hasCapture}
            endpoints={filteredEndpoints}
            selectedEndpoint={selectedEndpoint}
            onSelectEndpoint={setSelectedEndpointKey}
          />

          <HTTPLoginDetailsPanel
            selectedEndpoint={selectedEndpoint}
            attempts={filteredAttempts}
            bruteforceCount={analysis.bruteforceCount}
            successCount={analysis.successCount}
          />
        </div>
      </CardContent>
    </Card>
  );
}
