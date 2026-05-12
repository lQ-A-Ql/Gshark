import { Database, RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import type { MySQLAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { InvestigationReportPanel } from "../../components/InvestigationReportPanel";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { useMiscModuleAnalysis } from "../hooks/useMiscModuleAnalysis";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";
import { useSentinel } from "../../state/SentinelContext";
import { MySQLSessionDetails } from "./MySQLSessionDetails";
import { MySQLSessionList } from "./MySQLSessionList";
import {
  filterMySQLSessions,
  MYSQL_SESSION_FILTERS,
  renderMySQLAnalysisText,
  selectMySQLSession,
  type MySQLSessionFilter,
} from "./MySQLSessionAnalysisUtils";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";

const EMPTY_ANALYSIS: MySQLAnalysis = {
  sessionCount: 0,
  loginCount: 0,
  queryCount: 0,
  errorCount: 0,
  resultsetCount: 0,
  sessions: [],
  notes: [],
  report: EMPTY_INVESTIGATION_REPORT,
};

export function MySQLSessionAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const fetchAnalysis = useCallback((signal: AbortSignal) => backendClients.analysis.getMySQLAnalysis(signal), []);
  const { analysis, loading, error, refresh } = useMiscModuleAnalysis<MySQLAnalysis>({
    fetch: fetchAnalysis,
    emptyData: EMPTY_ANALYSIS,
    errorMessage: "加载 MySQL 会话重建失败",
  });
  const [sessionFilter, setSessionFilter] = useState<MySQLSessionFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";

  const filteredSessions = useMemo(() => {
    return filterMySQLSessions(analysis.sessions, sessionFilter, query);
  }, [analysis.sessions, query, sessionFilter]);

  const selectedSession = useMemo(
    () => selectMySQLSession(filteredSessions, selectedStreamId),
    [filteredSessions, selectedStreamId],
  );

  function exportAnalysis(format: MiscExportFormat) {
    exportStructuredResult({
      filenameBase: "mysql-session-analysis",
      format,
      payload: analysis,
      renderText: renderMySQLAnalysisText,
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
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-100 text-emerald-700">
            <Database className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
        <div className="flex flex-wrap gap-2 rounded-xl border border-emerald-100 bg-emerald-50/50 p-4 text-[11px] shadow-sm">
          <MetaChip label="抓包" value={hasCapture ? fileMeta.name : "未加载"} color={hasCapture ? "sky" : "slate"} />
          <MetaChip label="会话" value={analysis.sessionCount} color="slate" />
          <MetaChip label="登录" value={analysis.loginCount} color={analysis.loginCount > 0 ? "emerald" : "slate"} />
          <MetaChip label="查询" value={analysis.queryCount} color="sky" />
          <MetaChip label="错误" value={analysis.errorCount} color={analysis.errorCount > 0 ? "rose" : "slate"} />
          <MetaChip label="结果集" value={analysis.resultsetCount} color="slate" />
          {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="会话筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {MYSQL_SESSION_FILTERS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setSessionFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    sessionFilter === item
                      ? "bg-white text-emerald-700 shadow-sm"
                      : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {item === "ALL" ? "全部" : item === "LOGIN" ? "登录" : "错误"}
                </button>
              ))}
            </div>
          </Field>
          <Field label="检索会话 / 用户 / 数据库 / SQL">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="user / db / select / insert / version / plugin"
              className="font-mono text-sm shadow-sm"
            />
          </Field>
          <div className="flex items-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => void refresh()}
              disabled={!hasCapture || loading}
              className="gap-2 bg-white text-emerald-700"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "分析中..." : "刷新"}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <ExportButtons disabled={analysis.sessionCount === 0} onExport={exportAnalysis} />
        </div>

        {!error && <NotesList notes={analysis.notes} />}
        {error && <ErrorBlock message={error} />}
        <InvestigationReportPanel report={analysis.report} preferredProtocol="TCP" />

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.94fr)_minmax(0,1.06fr)]">
          <MySQLSessionList
            sessions={filteredSessions}
            selectedStreamId={selectedSession?.streamId}
            hasCapture={hasCapture}
            onSelectSession={setSelectedStreamId}
          />
          <MySQLSessionDetails session={selectedSession} />
        </div>
      </CardContent>
    </Card>
  );
}
