import { Mail, RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import type { SMTPAnalysis } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { useMiscModuleAnalysis } from "../hooks/useMiscModuleAnalysis";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";
import { SMTPSessionDetailsPanel } from "./SMTPSessionDetailsPanel";
import { SMTPSessionList } from "./SMTPSessionList";
import {
  countSMTPSessionMessages,
  filterSMTPSessions,
  renderSMTPAnalysisText,
  selectSMTPSession,
  SMTP_SESSION_FILTERS,
  type SMTPSessionFilter,
} from "./SMTPSessionAnalysisUtils";

const EMPTY_ANALYSIS: SMTPAnalysis = {
  sessionCount: 0,
  messageCount: 0,
  authCount: 0,
  attachmentHintCount: 0,
  sessions: [],
  notes: [],
};

export function SMTPSessionAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const fetchAnalysis = useCallback((signal: AbortSignal) => bridge.getSMTPAnalysis(signal), []);
  const { analysis, loading, error, refresh } = useMiscModuleAnalysis<SMTPAnalysis>({
    fetch: fetchAnalysis,
    emptyData: EMPTY_ANALYSIS,
    errorMessage: "加载 SMTP 会话重建失败",
  });
  const [sessionFilter, setSessionFilter] = useState<SMTPSessionFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";

  const filteredSessions = useMemo(() => {
    return filterSMTPSessions(analysis.sessions, sessionFilter, query);
  }, [analysis.sessions, query, sessionFilter]);

  const selectedSession = useMemo(
    () => selectSMTPSession(filteredSessions, selectedStreamId),
    [filteredSessions, selectedStreamId],
  );

  const filteredMessageCount = useMemo(() => countSMTPSessionMessages(filteredSessions), [filteredSessions]);

  function exportAnalysis(format: MiscExportFormat) {
    exportStructuredResult({
      filenameBase: "smtp-session-analysis",
      format,
      payload: analysis,
      renderText: renderSMTPAnalysisText,
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
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-100 text-sky-600">
            <Mail className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
        <div className="flex flex-wrap gap-2 rounded-xl border border-sky-100 bg-sky-50/50 p-4 text-[11px] shadow-sm">
          <MetaChip label="抓包" value={hasCapture ? fileMeta.name : "未加载"} color={hasCapture ? "sky" : "slate"} />
          <MetaChip label="会话" value={analysis.sessionCount} color="slate" />
          <MetaChip label="邮件" value={analysis.messageCount} color="emerald" />
          <MetaChip label="认证" value={analysis.authCount} color={analysis.authCount > 0 ? "rose" : "slate"} />
          <MetaChip
            label="附件线索"
            value={analysis.attachmentHintCount}
            color={analysis.attachmentHintCount > 0 ? "sky" : "slate"}
          />
          {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="会话筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {SMTP_SESSION_FILTERS.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setSessionFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    sessionFilter === item ? "bg-white text-sky-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {item === "ALL" ? "全部" : item === "AUTH" ? "认证" : "附件"}
                </button>
              ))}
            </div>
          </Field>
          <Field label="检索会话 / 邮件头 / 收件人">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="stream / HELO / username / MAIL FROM / RCPT TO / Subject"
              className="font-mono text-sm shadow-sm"
            />
          </Field>
          <div className="flex items-end gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => void refresh()}
              disabled={!hasCapture || loading}
              className="gap-2 bg-white text-sky-700"
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

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.96fr)_minmax(0,1.04fr)]">
          <SMTPSessionList
            hasCapture={hasCapture}
            sessions={filteredSessions}
            selectedSession={selectedSession}
            messageCount={filteredMessageCount}
            onSelectSession={setSelectedStreamId}
          />

          <SMTPSessionDetailsPanel selectedSession={selectedSession} />
        </div>
      </CardContent>
    </Card>
  );
}
