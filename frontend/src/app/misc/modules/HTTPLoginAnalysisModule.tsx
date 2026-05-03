import { AlertTriangle, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { HTTPLoginAnalysis, HTTPLoginEndpoint } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";

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
};

type ResultFilter = "ALL" | "SUCCESS" | "FAILURE" | "UNCERTAIN";

export function HTTPLoginAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<HTTPLoginAnalysis>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedEndpointKey, setSelectedEndpointKey] = useState("");
  const embedded = surfaceVariant === "embedded";
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const loadAnalysis = useCallback((preserveSelection = false) => {
    if (!hasCapture) {
      cancelAnalysisRequest();
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedEndpointKey("");
      setError("");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getHTTPLoginAnalysis(signal),
      onSuccess: (payload) => {
        setAnalysis(payload);
        setSelectedEndpointKey((current) => preserveSelection && current && payload.endpoints.some((item) => item.key === current) ? current : payload.endpoints[0]?.key ?? "");
      },
      onError: (err) => {
        setAnalysis(EMPTY_ANALYSIS);
        setSelectedEndpointKey("");
        setError(err instanceof Error ? err.message : "加载 HTTP 登录行为分析失败");
      },
      onSettled: () => setLoading(false),
    });
  }, [cancelAnalysisRequest, hasCapture, runAnalysisRequest]);

  useEffect(() => loadAnalysis(false), [fileMeta.path, loadAnalysis]);

  function refresh() {
    loadAnalysis(true);
  }

  const filteredEndpoints = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    return analysis.endpoints.filter((item) => {
      if (resultFilter === "SUCCESS" && item.successCount <= 0) return false;
      if (resultFilter === "FAILURE" && item.failureCount <= 0) return false;
      if (resultFilter === "UNCERTAIN" && item.uncertainCount <= 0) return false;
      if (!keyword) return true;
      const haystack = [
        item.key,
        item.method,
        item.host,
        item.path,
        item.requestKeys?.join(" "),
        item.responseIndicators?.join(" "),
        item.notes?.join(" "),
      ].join(" ").toLowerCase();
      return haystack.includes(keyword);
    });
  }, [analysis.endpoints, query, resultFilter]);

  const selectedEndpoint = useMemo(
    () => filteredEndpoints.find((item) => item.key === selectedEndpointKey) ?? filteredEndpoints[0] ?? null,
    [filteredEndpoints, selectedEndpointKey],
  );

  const filteredAttempts = useMemo(() => {
    if (!selectedEndpoint) return [];
    return analysis.attempts.filter((item) => endpointKeyForAttempt(item) === selectedEndpoint.key);
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
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
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
          <MetaChip label="疑似爆破" value={analysis.bruteforceCount} color={analysis.bruteforceCount > 0 ? "rose" : "slate"} />
        </div>

        <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="结果筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {(["ALL", "SUCCESS", "FAILURE", "UNCERTAIN"] as ResultFilter[]).map((item) => (
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
            <Button type="button" variant="outline" onClick={() => void refresh()} disabled={!hasCapture || loading} className="gap-2 bg-white text-cyan-700">
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

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.92fr)_minmax(0,1.08fr)]">
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-800">认证端点</div>
              <div className="text-[11px] text-slate-500">{filteredEndpoints.length} 条</div>
            </div>
            <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
              {filteredEndpoints.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
                  {hasCapture ? "未识别到符合条件的 HTTP 登录端点" : "未加载抓包"}
                </div>
              ) : (
                filteredEndpoints.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => setSelectedEndpointKey(item.key)}
                    className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                      selectedEndpoint?.key === item.key
                        ? "border-cyan-400 bg-cyan-50 shadow-sm ring-2 ring-cyan-100"
                        : "border-slate-200 bg-white hover:border-cyan-200 hover:bg-cyan-50/40"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 font-mono text-[11px] font-semibold text-cyan-700">{item.method || "HTTP"}</span>
                      {item.possibleBruteforce && (
                        <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">疑似爆破</span>
                      )}
                      <span className="text-[11px] text-slate-500">{item.attemptCount} 次尝试</span>
                    </div>
                    <div className="mt-2 break-all font-medium text-slate-800">{renderEndpointTitle(item)}</div>
                    <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                      <span>成功 {item.successCount}</span>
                      <span>失败 {item.failureCount}</span>
                      <span>待确认 {item.uncertainCount}</span>
                      {item.usernameVariants ? <span>用户变体 {item.usernameVariants}</span> : null}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-semibold text-slate-800">端点详情</div>
                  <div className="text-[12px] text-slate-500">聚合查看参数键、状态码分布、响应信号与疑似爆破线索。</div>
                </div>
              </div>
              {!selectedEndpoint ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                  请选择左侧的一个认证端点查看详情。
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <MetaChip label="Method" value={selectedEndpoint.method || "HTTP"} color="sky" />
                    <MetaChip label="Host" value={selectedEndpoint.host || "--"} color="slate" />
                    <MetaChip label="Path" value={selectedEndpoint.path || "/"} color="slate" />
                    <MetaChip label="尝试" value={selectedEndpoint.attemptCount} color="slate" />
                    <MetaChip label="Set-Cookie" value={selectedEndpoint.setCookieCount || 0} color="emerald" />
                    <MetaChip label="Token" value={selectedEndpoint.tokenHintCount || 0} color="sky" />
                  </div>

                  <div className="grid gap-3 md:grid-cols-2">
                    <InfoBlock title="请求键" values={selectedEndpoint.requestKeys} empty="无已提取参数键" />
                    <InfoBlock title="响应信号" values={selectedEndpoint.responseIndicators} empty="无明显响应信号" />
                    <InfoBlock title="状态码分布" values={(selectedEndpoint.statusCodes ?? []).map((item) => `${item.label} × ${item.count}`)} empty="无状态码" />
                    <InfoBlock title="端点说明" values={selectedEndpoint.notes} empty="暂无说明" />
                  </div>
                </div>
              )}
            </div>

            <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
              <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/80 px-4 py-3">
                <div>
                  <div className="text-sm font-semibold text-slate-800">认证尝试明细</div>
                  <div className="mt-0.5 text-[11px] text-slate-500">按包号串联请求、响应、凭据线索与判定原因。</div>
                </div>
                <span className="shrink-0 rounded-full border border-cyan-200 bg-cyan-50 px-2.5 py-1 text-[11px] font-semibold text-cyan-700">
                  {filteredAttempts.length} 条
                </span>
              </div>
              <DataTable
                data={filteredAttempts}
                rowKey={(item) => `${item.packetId}-${item.responsePacketId || 0}`}
                maxHeightClassName="max-h-[460px]"
                tableClassName="min-w-[1040px] border-separate border-spacing-0"
                wrapperClassName="rounded-none border-0 bg-white"
                headerClassName="z-10 bg-slate-100/95 text-[11px] uppercase tracking-[0.12em] shadow-[0_1px_0_0_rgba(148,163,184,0.35)] backdrop-blur"
                headerCellClassName="py-3 font-semibold"
                emptyText="暂无认证尝试"
                rowClassName="odd:bg-white even:bg-slate-50/45 hover:bg-cyan-50/45"
                cellClassName="py-3"
                columns={[
                  {
                    key: "request",
                    header: "请求包",
                    widthClassName: "w-[84px]",
                    headerClassName: "whitespace-nowrap",
                    cellClassName: "whitespace-nowrap font-mono text-[12px] font-semibold text-slate-800",
                    render: (item) => `#${item.packetId}`,
                  },
                  {
                    key: "response",
                    header: "响应包",
                    widthClassName: "w-[84px]",
                    headerClassName: "whitespace-nowrap",
                    cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-600",
                    render: (item) => item.responsePacketId ? `#${item.responsePacketId}` : "--",
                  },
                  {
                    key: "result",
                    header: "结果",
                    widthClassName: "w-[104px]",
                    headerClassName: "whitespace-nowrap",
                    cellClassName: "whitespace-nowrap",
                    render: (item) => <span className={attemptBadge(item.result, item.possibleBruteforce)}>{renderAttemptLabel(item.result, item.possibleBruteforce)}</span>,
                  },
                  {
                    key: "status",
                    header: "状态码",
                    widthClassName: "w-[84px]",
                    headerClassName: "whitespace-nowrap",
                    cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-700",
                    render: (item) => item.statusCode || "--",
                  },
                  {
                    key: "username",
                    header: "用户名",
                    widthClassName: "w-[140px]",
                    headerClassName: "whitespace-nowrap",
                    render: (item) => <div className="max-w-[128px] truncate font-mono text-[11px] text-slate-700" title={item.username || "--"}>{item.username || "--"}</div>,
                  },
                  {
                    key: "keys",
                    header: "参数键",
                    widthClassName: "w-[170px]",
                    headerClassName: "whitespace-nowrap",
                    render: (item) => {
                      const keys = (item.requestKeys ?? []).join(", ") || "--";
                      return <div className="max-w-[158px] truncate font-mono text-[11px] text-slate-600" title={keys}>{keys}</div>;
                    },
                  },
                  {
                    key: "reason",
                    header: "原因",
                    widthClassName: "w-[190px]",
                    headerClassName: "whitespace-nowrap",
                    cellClassName: "text-[12px] leading-relaxed text-slate-700",
                    render: (item) => item.reason || "--",
                  },
                  {
                    key: "preview",
                    header: "请求 / 响应预览",
                    headerClassName: "min-w-[300px] whitespace-nowrap",
                    render: (item) => (
                      <div className="space-y-1.5">
                        <PreviewLine label="REQ" value={item.requestPreview || "--"} tone="sky" />
                        {item.responsePreview ? <PreviewLine label="RESP" value={item.responsePreview} tone="slate" /> : null}
                      </div>
                    ),
                  },
                ]}
              />
            </div>

            {analysis.bruteforceCount > 0 && (
              <div className="rounded-xl border border-rose-200 bg-rose-50/80 p-4 text-sm text-rose-800 shadow-sm">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertTriangle className="h-4 w-4" />
                  发现疑似爆破 / 批量验证
                </div>
                <div className="mt-2 text-[13px] leading-relaxed">
                  当前结果中共有 {analysis.bruteforceCount} 个认证端点命中爆破特征，建议优先回到 HTTP 流追踪页复核失败序列、用户名变化和限速/验证码响应。
                </div>
              </div>
            )}
            {analysis.successCount > 0 && (
              <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm text-emerald-800 shadow-sm">
                <div className="flex items-center gap-2 font-semibold">
                  <ShieldCheck className="h-4 w-4" />
                  已识别成功认证信号
                </div>
                <div className="mt-2 text-[13px] leading-relaxed">
                  成功线索通常来自 2xx/3xx + Set-Cookie、token 返回或跳转到非登录页面。你可以结合包号和 stream 继续向下追踪后续会话行为。
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function endpointKeyForAttempt(item: HTTPLoginAnalysis["attempts"][number]) {
  return `${String(item.method ?? "").trim().toUpperCase()}|${String(item.host ?? "").trim()}|${String(item.path ?? "").trim()}`;
}

function renderEndpointTitle(item: HTTPLoginEndpoint) {
  const base = item.host ? `${item.host}${item.path || "/"}` : item.path || "/";
  return `${item.method || "HTTP"} ${base}`;
}

function InfoBlock({ title, values, empty }: { title: string; values?: string[]; empty: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</div>
      {(values?.length ?? 0) > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values!.map((value) => (
            <span key={value} className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] text-slate-700">{value}</span>
          ))}
        </div>
      ) : (
        <div className="text-[12px] text-slate-500">{empty}</div>
      )}
    </div>
  );
}

function PreviewLine({ label, value, tone }: { label: string; value: string; tone: "sky" | "slate" }) {
  return (
    <div
      className={`flex min-w-0 items-start gap-2 rounded-lg border px-2.5 py-2 ${
        tone === "sky" ? "border-sky-100 bg-sky-50/70 text-sky-900" : "border-slate-100 bg-slate-50 text-slate-700"
      }`}
    >
      <span
        className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-[0.12em] ${
          tone === "sky" ? "bg-sky-100 text-sky-700" : "bg-slate-200/70 text-slate-600"
        }`}
      >
        {label}
      </span>
      <span className="min-w-0 break-all font-mono text-[11px] leading-relaxed">{value}</span>
    </div>
  );
}

function attemptBadge(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "rounded border border-rose-200 bg-rose-50 px-2 py-0.5 text-rose-700";
  switch (result) {
    case "success":
      return "rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-emerald-700";
    case "failure":
      return "rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-amber-700";
    default:
      return "rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-slate-700";
  }
}

function renderAttemptLabel(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "疑似爆破";
  switch (result) {
    case "success":
      return "成功";
    case "failure":
      return "失败";
    default:
      return "待确认";
  }
}

function renderHTTPLoginAnalysisText(analysis: HTTPLoginAnalysis) {
  const lines: string[] = [
    "HTTP 登录行为分析",
    `总尝试: ${analysis.totalAttempts}`,
    `候选端点: ${analysis.candidateEndpoints}`,
    `成功: ${analysis.successCount}`,
    `失败: ${analysis.failureCount}`,
    `待确认: ${analysis.uncertainCount}`,
    `疑似爆破: ${analysis.bruteforceCount}`,
    "",
    "端点详情:",
  ];
  for (const endpoint of analysis.endpoints) {
    lines.push(`- ${renderEndpointTitle(endpoint)}`);
    lines.push(`  尝试 ${endpoint.attemptCount} / 成功 ${endpoint.successCount} / 失败 ${endpoint.failureCount} / 待确认 ${endpoint.uncertainCount}`);
    if (endpoint.possibleBruteforce) {
      lines.push("  标记: 疑似爆破");
    }
    if ((endpoint.requestKeys?.length ?? 0) > 0) {
      lines.push(`  请求键: ${endpoint.requestKeys!.join(", ")}`);
    }
    if ((endpoint.responseIndicators?.length ?? 0) > 0) {
      lines.push(`  响应信号: ${endpoint.responseIndicators!.join(", ")}`);
    }
  }
  return lines.join("\n");
}
