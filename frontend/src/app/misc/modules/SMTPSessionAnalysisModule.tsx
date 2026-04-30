import { Mail, Paperclip, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { SMTPAnalysis, SMTPSession } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";

const EMPTY_ANALYSIS: SMTPAnalysis = {
  sessionCount: 0,
  messageCount: 0,
  authCount: 0,
  attachmentHintCount: 0,
  sessions: [],
  notes: [],
};

type SessionFilter = "ALL" | "AUTH" | "ATTACHMENT";

export function SMTPSessionAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<SMTPAnalysis>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sessionFilter, setSessionFilter] = useState<SessionFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedStreamId, setSelectedStreamId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";

  async function loadAnalysis() {
    if (!hasCapture) {
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedStreamId(0);
      setError("");
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError("");
    try {
      const payload = await bridge.getSMTPAnalysis(controller.signal);
      setAnalysis(payload);
      setSelectedStreamId((current) => current && payload.sessions.some((item) => item.streamId === current) ? current : payload.sessions[0]?.streamId ?? 0);
    } catch (err) {
      if (controller.signal.aborted) return;
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedStreamId(0);
      setError(err instanceof Error ? err.message : "加载 SMTP 会话重建失败");
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    if (!hasCapture) {
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedStreamId(0);
      setError("");
      setLoading(false);
      return () => controller.abort();
    }
    setLoading(true);
    setError("");
    void bridge.getSMTPAnalysis(controller.signal)
      .then((payload) => {
        setAnalysis(payload);
        setSelectedStreamId(payload.sessions[0]?.streamId ?? 0);
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setAnalysis(EMPTY_ANALYSIS);
        setSelectedStreamId(0);
        setError(err instanceof Error ? err.message : "加载 SMTP 会话重建失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [hasCapture, fileMeta.path]);

  const filteredSessions = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    return analysis.sessions.filter((item) => {
      if (sessionFilter === "AUTH" && !item.authUsername && (item.authMechanisms?.length ?? 0) === 0) return false;
      if (sessionFilter === "ATTACHMENT" && (item.attachmentHints ?? 0) <= 0) return false;
      if (!keyword) return true;
      const haystack = [
        item.streamId,
        item.client,
        item.server,
        item.helo,
        item.authUsername,
        item.mailFrom?.join(" "),
        item.rcptTo?.join(" "),
        item.authMechanisms?.join(" "),
        item.statusHints?.join(" "),
        item.messages?.map((row) => [row.subject, row.from, row.to, row.attachmentNames?.join(" "), row.bodyPreview].join(" ")).join(" "),
      ].join(" ").toLowerCase();
      return haystack.includes(keyword);
    });
  }, [analysis.sessions, query, sessionFilter]);

  const selectedSession = useMemo(
    () => filteredSessions.find((item) => item.streamId === selectedStreamId) ?? filteredSessions[0] ?? null,
    [filteredSessions, selectedStreamId],
  );

  const filteredMessageCount = useMemo(
    () => filteredSessions.reduce((sum, item) => sum + (item.messageCount ?? item.messages?.length ?? 0), 0),
    [filteredSessions],
  );

  function exportAnalysis(format: MiscExportFormat) {
    exportStructuredResult({
      filenameBase: "smtp-session-analysis",
      format,
      payload: analysis,
      renderText: renderSMTPAnalysisText,
    });
  }

  return (
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
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
          <MetaChip label="附件线索" value={analysis.attachmentHintCount} color={analysis.attachmentHintCount > 0 ? "sky" : "slate"} />
          {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="会话筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {(["ALL", "AUTH", "ATTACHMENT"] as SessionFilter[]).map((item) => (
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
            <Button type="button" variant="outline" onClick={() => void loadAnalysis()} disabled={!hasCapture || loading} className="gap-2 bg-white text-sky-700">
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
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-800">SMTP 会话列表</div>
              <div className="text-[11px] text-slate-500">{filteredSessions.length} 条 / 邮件 {filteredMessageCount}</div>
            </div>
            <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
              {filteredSessions.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
                  {hasCapture ? "当前筛选下没有匹配的 SMTP 会话" : "未加载抓包"}
                </div>
              ) : (
                filteredSessions.map((item) => {
                  const selected = selectedSession?.streamId === item.streamId;
                  return (
                    <button
                      key={`smtp-session-${item.streamId}`}
                      type="button"
                      onClick={() => setSelectedStreamId(item.streamId)}
                      className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                        selected
                          ? "border-sky-400 bg-sky-50 shadow-sm ring-2 ring-sky-100"
                          : "border-slate-200 bg-white hover:border-sky-200 hover:bg-sky-50/40"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-sky-200 bg-sky-50 px-2 py-1 font-mono text-[11px] font-semibold text-sky-700">SMTP #{item.streamId}</span>
                        {item.authUsername || (item.authMechanisms?.length ?? 0) > 0 ? (
                          <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">认证</span>
                        ) : null}
                        {(item.attachmentHints ?? 0) > 0 ? (
                          <span className="rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">附件 {item.attachmentHints}</span>
                        ) : null}
                        {item.possibleCleartext ? (
                          <span className="rounded-md bg-amber-100 px-2 py-1 text-[11px] font-semibold text-amber-700">明文凭据风险</span>
                        ) : null}
                      </div>
                      <div className="mt-2 break-all font-medium text-slate-800">{renderSessionTitle(item)}</div>
                      <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                        <span>命令 {item.commandCount}</span>
                        <span>邮件 {item.messageCount}</span>
                        {(item.mailFrom?.length ?? 0) > 0 ? <span>发件人 {item.mailFrom?.length}</span> : null}
                        {(item.rcptTo?.length ?? 0) > 0 ? <span>收件人 {item.rcptTo?.length}</span> : null}
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
                  <div className="text-[12px] text-slate-500">查看认证、MAIL FROM / RCPT TO、状态提示与明文风险。</div>
                </div>
              </div>
              {!selectedSession ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                  请选择左侧的一条 SMTP 会话查看详情。
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <MetaChip label="Stream" value={selectedSession.streamId} color="sky" />
                    <MetaChip label="客户端" value={selectedSession.client ? `${selectedSession.client}${selectedSession.clientPort ? `:${selectedSession.clientPort}` : ""}` : "--"} color="slate" />
                    <MetaChip label="服务端" value={selectedSession.server ? `${selectedSession.server}${selectedSession.serverPort ? `:${selectedSession.serverPort}` : ""}` : "--"} color="slate" />
                    <MetaChip label="HELO" value={selectedSession.helo || "--"} color="slate" />
                    <MetaChip label="机制" value={selectedSession.authMechanisms?.join(", ") || "--"} color={(selectedSession.authMechanisms?.length ?? 0) > 0 ? "rose" : "slate"} />
                  </div>

                  <div className="grid gap-3 md:grid-cols-2">
                    <InfoBlock title="认证用户名" values={selectedSession.authUsername ? [selectedSession.authUsername] : []} empty="未解析到用户名" tone="rose" />
                    <InfoBlock title="状态提示" values={selectedSession.statusHints ?? []} empty="暂无状态提示" tone="slate" />
                    <InfoBlock title="MAIL FROM" values={selectedSession.mailFrom ?? []} empty="无 MAIL FROM" tone="sky" />
                    <InfoBlock title="RCPT TO" values={selectedSession.rcptTo ?? []} empty="无 RCPT TO" tone="sky" />
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[12px] text-slate-600">
                    <div className="flex items-center gap-2 font-semibold text-slate-700">
                      <ShieldCheck className="h-4 w-4 text-sky-600" />
                      认证观察
                    </div>
                    <div className="mt-2 leading-relaxed">
                      {selectedSession.authUsername || (selectedSession.authMechanisms?.length ?? 0) > 0
                        ? `${selectedSession.authPasswordSeen ? "检测到密码材料经过明文或可逆 Base64 传输。" : "检测到 SMTP AUTH 协商，但未直接看到密码正文。"}${selectedSession.possibleCleartext ? " 建议结合 STARTTLS / TLS 解密确认是否存在明文暴露。" : ""}`
                        : "该会话未检测到明显的 SMTP AUTH 材料，更偏向普通投递或服务器响应流。"}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div className="text-sm font-semibold text-slate-800">邮件重建</div>
                <div className="text-[11px] text-slate-500">{selectedSession?.messages?.length ?? 0} 条</div>
              </div>
              {!selectedSession || (selectedSession.messages?.length ?? 0) === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                  该 SMTP 会话暂未重建出邮件正文。
                </div>
              ) : (
                <div className="max-h-[420px] space-y-3 overflow-auto pr-1">
                  {(selectedSession.messages ?? []).map((message) => (
                    <div key={`${selectedSession.streamId}-${message.sequence}`} className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-sky-200 bg-white px-2 py-1 text-[11px] font-semibold text-sky-700">邮件 #{message.sequence}</span>
                        {message.subject ? <span className="text-sm font-semibold text-slate-800">{message.subject}</span> : <span className="text-sm text-slate-500">(无主题)</span>}
                        {(message.attachmentNames?.length ?? 0) > 0 ? (
                          <span className="inline-flex items-center gap-1 rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">
                            <Paperclip className="h-3.5 w-3.5" />
                            {message.attachmentNames?.length} 个附件线索
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-2 grid gap-3 md:grid-cols-2">
                        <MiniField label="From" value={message.from || message.mailFrom || "--"} />
                        <MiniField label="To" value={message.to || message.rcptTo?.join(", ") || "--"} />
                        <MiniField label="Date" value={message.date || "--"} />
                        <MiniField label="Content-Type" value={message.contentType || "--"} />
                      </div>
                      {(message.attachmentNames?.length ?? 0) > 0 && (
                        <div className="mt-3">
                          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">附件文件名</div>
                          <div className="flex flex-wrap gap-2">
                            {message.attachmentNames?.map((name) => (
                              <span key={`${message.sequence}-${name}`} className="rounded-md border border-sky-200 bg-white px-2 py-1 font-mono text-[11px] text-sky-700">{name}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-600">
                        {message.bodyPreview || "无正文预览"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div className="text-sm font-semibold text-slate-800">命令轨迹</div>
                <div className="text-[11px] text-slate-500">{selectedSession?.commands?.length ?? 0} 条</div>
              </div>
              <DataTable
                data={selectedSession?.commands ?? []}
                rowKey={(command) => `${selectedSession?.streamId ?? "smtp"}-${command.packetId}-${command.summary || command.command || command.statusCode || "row"}`}
                maxHeightClassName="max-h-[320px]"
                wrapperClassName="border-slate-100 bg-white"
                headerClassName="bg-slate-50/95 text-slate-500"
                emptyText="暂无命令轨迹"
                rowClassName="hover:bg-sky-50/40"
                columns={[
                  {
                    key: "packet",
                    header: "包号",
                    widthClassName: "w-20",
                    cellClassName: "font-mono text-slate-700",
                    render: (command) => command.packetId,
                  },
                  {
                    key: "direction",
                    header: "方向",
                    widthClassName: "w-20",
                    render: (command) => command.direction || "--",
                  },
                  {
                    key: "command",
                    header: "命令",
                    widthClassName: "w-24",
                    cellClassName: "font-mono text-slate-700",
                    render: (command) => command.command || "--",
                  },
                  {
                    key: "status",
                    header: "状态码",
                    widthClassName: "w-20",
                    cellClassName: "font-mono text-slate-700",
                    render: (command) => command.statusCode || "--",
                  },
                  {
                    key: "summary",
                    header: "摘要",
                    cellClassName: "break-all text-slate-700",
                    render: (command) => command.summary || command.argument || "--",
                  },
                ]}
              />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function renderSessionTitle(session: SMTPSession) {
  const left = session.client ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}` : `stream #${session.streamId}`;
  const right = session.server ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}` : "SMTP server";
  return `${left} → ${right}`;
}

function renderSMTPAnalysisText(analysis: SMTPAnalysis) {
  const lines: string[] = [
    `SMTP session count: ${analysis.sessionCount}`,
    `message count: ${analysis.messageCount}`,
    `auth count: ${analysis.authCount}`,
    `attachment hints: ${analysis.attachmentHintCount}`,
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
    lines.push(`[SMTP stream #${session.streamId}] ${renderSessionTitle(session)}`);
    lines.push(`HELO: ${session.helo || "--"}`);
    lines.push(`AUTH: ${(session.authMechanisms ?? []).join(", ") || "--"}`);
    lines.push(`AUTH username: ${session.authUsername || "--"}`);
    lines.push(`MAIL FROM: ${(session.mailFrom ?? []).join(", ") || "--"}`);
    lines.push(`RCPT TO: ${(session.rcptTo ?? []).join(", ") || "--"}`);
    lines.push(`Status: ${(session.statusHints ?? []).join(", ") || "--"}`);
    lines.push(`Messages: ${session.messageCount}`);
    for (const message of session.messages ?? []) {
      lines.push(`  - Message #${message.sequence}: ${message.subject || "(no subject)"}`);
      if (message.from) lines.push(`    From: ${message.from}`);
      if (message.to) lines.push(`    To: ${message.to}`);
      if (message.attachmentNames?.length) lines.push(`    Attachments: ${message.attachmentNames.join(", ")}`);
      if (message.bodyPreview) lines.push(`    Body: ${message.bodyPreview}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function InfoBlock({ title, values, empty, tone = "slate" }: { title: string; values?: string[]; empty: string; tone?: "slate" | "rose" | "sky" }) {
  const toneClass = tone === "rose"
    ? "border-rose-200 bg-rose-50/40"
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

function MiniField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 break-all text-[12px] text-slate-700">{value}</div>
    </div>
  );
}
