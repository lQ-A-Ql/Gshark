import { Database, RefreshCw, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { MySQLAnalysis, MySQLSession } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";

const EMPTY_ANALYSIS: MySQLAnalysis = {
  sessionCount: 0,
  loginCount: 0,
  queryCount: 0,
  errorCount: 0,
  resultsetCount: 0,
  sessions: [],
  notes: [],
};

type SessionFilter = "ALL" | "LOGIN" | "ERROR";

export function MySQLSessionAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<MySQLAnalysis>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sessionFilter, setSessionFilter] = useState<SessionFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";

  useEffect(() => {
    const controller = new AbortController();
    if (!hasCapture) {
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedStreamId(0);
      setLoading(false);
      setError("");
      return () => controller.abort();
    }
    setLoading(true);
    setError("");
    void bridge.getMySQLAnalysis(controller.signal)
      .then((payload) => {
        setAnalysis(payload);
        setSelectedStreamId(payload.sessions[0]?.streamId ?? 0);
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setAnalysis(EMPTY_ANALYSIS);
        setSelectedStreamId(0);
        setError(err instanceof Error ? err.message : "加载 MySQL 会话重建失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [hasCapture, fileMeta.path]);

  async function refresh() {
    if (!hasCapture) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    try {
      const payload = await bridge.getMySQLAnalysis(controller.signal);
      setAnalysis(payload);
      setSelectedStreamId((current) => current && payload.sessions.some((item) => item.streamId === current) ? current : payload.sessions[0]?.streamId ?? 0);
    } catch (err) {
      if (controller.signal.aborted) return;
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedStreamId(0);
      setError(err instanceof Error ? err.message : "加载 MySQL 会话重建失败");
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false);
      }
    }
  }

  const filteredSessions = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    return analysis.sessions.filter((item) => {
      if (sessionFilter === "LOGIN" && !item.username) return false;
      if (sessionFilter === "ERROR" && item.errCount <= 0) return false;
      if (!keyword) return true;
      const haystack = [
        item.streamId,
        item.client,
        item.server,
        item.username,
        item.database,
        item.serverVersion,
        item.authPlugin,
        item.commandTypes?.join(" "),
        item.notes?.join(" "),
        item.queries.map((row) => [row.command, row.sql, row.database, row.responseKind, row.responseSummary].join(" ")).join(" "),
      ].join(" ").toLowerCase();
      return haystack.includes(keyword);
    });
  }, [analysis.sessions, query, sessionFilter]);

  const selectedSession = useMemo(
    () => filteredSessions.find((item) => item.streamId === selectedStreamId) ?? filteredSessions[0] ?? null,
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
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
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
              {(["ALL", "LOGIN", "ERROR"] as SessionFilter[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setSessionFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    sessionFilter === item ? "bg-white text-emerald-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
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
            <Button type="button" variant="outline" onClick={() => void refresh()} disabled={!hasCapture || loading} className="gap-2 bg-white text-emerald-700">
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

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.94fr)_minmax(0,1.06fr)]">
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-800">MySQL 会话列表</div>
              <div className="text-[11px] text-slate-500">{filteredSessions.length} 条</div>
            </div>
            <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
              {filteredSessions.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
                  {hasCapture ? "当前筛选下没有匹配的 MySQL 会话" : "未加载抓包"}
                </div>
              ) : (
                filteredSessions.map((item) => {
                  const selected = selectedSession?.streamId === item.streamId;
                  return (
                    <button
                      key={`mysql-session-${item.streamId}`}
                      type="button"
                      onClick={() => setSelectedStreamId(item.streamId)}
                      className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                        selected
                          ? "border-emerald-400 bg-emerald-50 shadow-sm ring-2 ring-emerald-100"
                          : "border-slate-200 bg-white hover:border-emerald-200 hover:bg-emerald-50/40"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 font-mono text-[11px] font-semibold text-emerald-700">MySQL #{item.streamId}</span>
                        {item.username ? <span className="rounded-md bg-emerald-100 px-2 py-1 text-[11px] font-semibold text-emerald-700">登录</span> : null}
                        {item.errCount > 0 ? <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">错误 {item.errCount}</span> : null}
                        {item.resultsetCount > 0 ? <span className="rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">结果集 {item.resultsetCount}</span> : null}
                      </div>
                      <div className="mt-2 break-all font-medium text-slate-800">{renderSessionTitle(item)}</div>
                      <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                        <span>查询 {item.queryCount}</span>
                        {item.username ? <span>用户 {item.username}</span> : null}
                        {item.database ? <span>数据库 {item.database}</span> : null}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-semibold text-slate-800">会话详情</div>
                  <div className="text-[12px] text-slate-500">查看握手版本、登录用户名、默认库、认证插件与查询统计。</div>
                </div>
              </div>
              {!selectedSession ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">请选择左侧一条 MySQL 会话查看详情。</div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <MetaChip label="Stream" value={selectedSession.streamId} color="sky" />
                    <MetaChip label="Server" value={selectedSession.server ? `${selectedSession.server}${selectedSession.serverPort ? `:${selectedSession.serverPort}` : ""}` : "--"} color="slate" />
                    <MetaChip label="Client" value={selectedSession.client ? `${selectedSession.client}${selectedSession.clientPort ? `:${selectedSession.clientPort}` : ""}` : "--"} color="slate" />
                    <MetaChip label="Version" value={selectedSession.serverVersion || "--"} color="slate" />
                    <MetaChip label="Plugin" value={selectedSession.authPlugin || "--"} color="slate" />
                    <MetaChip label="登录状态" value={selectedSession.loginPacketId ? (selectedSession.loginSuccess ? "成功" : "失败/未知") : "未识别"} color={selectedSession.loginSuccess ? "emerald" : selectedSession.loginPacketId ? "rose" : "slate"} />
                  </div>

                  <div className="grid gap-3 md:grid-cols-2">
                    <InfoBlock title="用户名" values={selectedSession.username ? [selectedSession.username] : []} empty="未识别到登录用户名" tone="emerald" />
                    <InfoBlock title="数据库" values={selectedSession.database ? [selectedSession.database] : []} empty="未识别默认数据库" tone="sky" />
                    <InfoBlock title="命令类型" values={selectedSession.commandTypes ?? []} empty="暂无命令类型" tone="slate" />
                    <InfoBlock title="会话说明" values={selectedSession.notes ?? []} empty="暂无额外说明" tone="slate" />
                  </div>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div className="text-sm font-semibold text-slate-800">查询轨迹</div>
                <div className="text-[11px] text-slate-500">{selectedSession?.queries.length ?? 0} 条</div>
              </div>
              <DataTable
                data={selectedSession?.queries ?? []}
                rowKey={(row) => `${selectedSession?.streamId ?? "mysql"}-${row.packetId}-${row.command || "row"}`}
                maxHeightClassName="max-h-[420px]"
                wrapperClassName="border-slate-100 bg-white"
                headerClassName="bg-slate-50/95 text-slate-500"
                emptyText="暂无查询轨迹"
                rowClassName="hover:bg-emerald-50/40"
                columns={[
                  {
                    key: "packet",
                    header: "请求包",
                    widthClassName: "w-20",
                    cellClassName: "font-mono text-slate-700",
                    render: (row) => row.packetId,
                  },
                  {
                    key: "command",
                    header: "命令",
                    widthClassName: "w-24",
                    cellClassName: "font-mono text-slate-700",
                    render: (row) => row.command || "--",
                  },
                  {
                    key: "response",
                    header: "响应",
                    widthClassName: "w-20",
                    render: (row) => row.responseKind ? <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${responseBadgeClass(row.responseKind)}`}>{row.responseKind}</span> : "--",
                  },
                  {
                    key: "code",
                    header: "代码",
                    widthClassName: "w-20",
                    cellClassName: "font-mono text-slate-700",
                    render: (row) => row.responseCode || "--",
                  },
                  {
                    key: "database",
                    header: "数据库",
                    widthClassName: "w-24",
                    cellClassName: "break-all font-mono text-slate-700",
                    render: (row) => row.database || "--",
                  },
                  {
                    key: "summary",
                    header: "SQL / 摘要",
                    cellClassName: "break-all font-mono text-[11px] text-slate-700",
                    render: (row) => row.sql || row.responseSummary || "--",
                  },
                ]}
              />
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div className="text-sm font-semibold text-slate-800">服务端事件</div>
                <div className="text-[11px] text-slate-500">{selectedSession?.serverEvents.length ?? 0} 条</div>
              </div>
              {!selectedSession || selectedSession.serverEvents.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">暂无服务端事件摘要</div>
              ) : (
                <div className="max-h-[280px] space-y-2 overflow-auto pr-1">
                  {selectedSession.serverEvents.map((event) => (
                    <div key={`${selectedSession.streamId}-${event.packetId}-${event.kind || "evt"}`} className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-emerald-200 bg-white px-2 py-1 text-[11px] font-semibold text-emerald-700">帧 #{event.packetId}</span>
                        <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${eventBadgeClass(event.kind)}`}>{event.kind || "UNKNOWN"}</span>
                        {event.code ? <span className="font-mono text-[11px] text-slate-500">code {event.code}</span> : null}
                        {event.sequence !== undefined ? <span className="font-mono text-[11px] text-slate-500">seq {event.sequence}</span> : null}
                      </div>
                      <div className="mt-2 break-all text-[12px] text-slate-600">{event.summary || "--"}</div>
                    </div>
                  ))}
                </div>
              )}
              {selectedSession && selectedSession.errCount > 0 && (
                <div className="mt-4 rounded-lg border border-rose-200 bg-rose-50 px-3 py-3 text-[12px] text-rose-700">
                  <div className="flex items-center gap-2 font-semibold">
                    <TriangleAlert className="h-4 w-4" />
                    错误响应观察
                  </div>
                  <div className="mt-2 leading-relaxed">该会话包含 {selectedSession.errCount} 条 MySQL 错误响应，建议结合查询轨迹排查失败登录、权限问题、SQL 语法错误或探测行为。</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function renderSessionTitle(session: MySQLSession) {
  const left = session.client ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}` : `stream #${session.streamId}`;
  const right = session.server ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}` : "MySQL server";
  return `${left} → ${right}`;
}

function renderMySQLAnalysisText(analysis: MySQLAnalysis) {
  const lines: string[] = [
    `MySQL session count: ${analysis.sessionCount}`,
    `login count: ${analysis.loginCount}`,
    `query count: ${analysis.queryCount}`,
    `error count: ${analysis.errorCount}`,
    `resultset count: ${analysis.resultsetCount}`,
    "",
  ];
  if (analysis.notes.length > 0) {
    lines.push("Notes:");
    for (const note of analysis.notes) {
      lines.push(`- ${note}`);
    }
    lines.push("");
  }
  for (const session of analysis.sessions) {
    lines.push(`[MySQL stream #${session.streamId}] ${renderSessionTitle(session)}`);
    lines.push(`Version: ${session.serverVersion || "--"}`);
    lines.push(`User: ${session.username || "--"}`);
    lines.push(`Database: ${session.database || "--"}`);
    lines.push(`Plugin: ${session.authPlugin || "--"}`);
    for (const row of session.queries) {
      lines.push(`  - ${row.command || "CMD"}: ${row.sql || row.database || row.responseSummary || "--"} [${row.responseKind || "--"}]`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function InfoBlock({ title, values, empty, tone = "slate" }: { title: string; values?: string[]; empty: string; tone?: "slate" | "emerald" | "sky" }) {
  const toneClass = tone === "emerald"
    ? "border-emerald-200 bg-emerald-50/40"
    : tone === "sky"
      ? "border-sky-200 bg-sky-50/40"
      : "border-slate-200 bg-slate-50/70";
  return (
    <div className={`rounded-lg border p-3 ${toneClass}`}>
      <div className="mb-2 text-[12px] font-semibold text-slate-700">{title}</div>
      {values && values.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <span key={`${title}-${value}`} className="rounded-md border border-white/80 bg-white px-2 py-1 font-mono text-[11px] text-slate-700 shadow-sm">{value}</span>
          ))}
        </div>
      ) : (
        <div className="text-[12px] text-slate-500">{empty}</div>
      )}
    </div>
  );
}

function responseBadgeClass(kind?: string) {
  switch (kind) {
    case "OK":
      return "bg-emerald-100 text-emerald-700";
    case "ERR":
      return "bg-rose-100 text-rose-700";
    case "RESULTSET":
      return "bg-sky-100 text-sky-700";
    default:
      return "bg-slate-100 text-slate-700";
  }
}

function eventBadgeClass(kind?: string) {
  switch (kind) {
    case "HANDSHAKE":
      return "bg-violet-100 text-violet-700";
    case "OK":
      return "bg-emerald-100 text-emerald-700";
    case "ERR":
      return "bg-rose-100 text-rose-700";
    case "RESULTSET":
      return "bg-sky-100 text-sky-700";
    default:
      return "bg-slate-100 text-slate-700";
  }
}
