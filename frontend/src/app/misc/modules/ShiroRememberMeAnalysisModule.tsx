import { KeyRound, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ShiroRememberMeAnalysis, ShiroRememberMeCandidate } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { EvidenceActions } from "../EvidenceActions";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip, NotesList } from "../ui";

const EMPTY_ANALYSIS: ShiroRememberMeAnalysis = {
  candidateCount: 0,
  hitCount: 0,
  candidates: [],
  notes: [],
};

type CandidateFilter = "ALL" | "HIT" | "DELETEME";

export function ShiroRememberMeAnalysisModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<ShiroRememberMeAnalysis>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [candidateFilter, setCandidateFilter] = useState<CandidateFilter>("ALL");
  const [customKeys, setCustomKeys] = useState("");
  const [selectedPacketId, setSelectedPacketId] = useState<number>(0);
  const embedded = surfaceVariant === "embedded";

  const keyLines = useMemo(
    () => customKeys.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [customKeys],
  );

  async function loadAnalysis(keys = keyLines) {
    if (!hasCapture) {
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedPacketId(0);
      setError("");
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError("");
    try {
      const payload = await bridge.getShiroRememberMeAnalysis(keys, controller.signal);
      setAnalysis(payload);
      setSelectedPacketId((current) => current && payload.candidates.some((item) => item.packetId === current) ? current : payload.candidates[0]?.packetId ?? 0);
    } catch (err) {
      if (controller.signal.aborted) return;
      setAnalysis(EMPTY_ANALYSIS);
      setSelectedPacketId(0);
      setError(err instanceof Error ? err.message : "加载 Shiro rememberMe 分析失败");
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
      setSelectedPacketId(0);
      setError("");
      setLoading(false);
      return () => controller.abort();
    }
    setLoading(true);
    setError("");
    void bridge.getShiroRememberMeAnalysis([], controller.signal)
      .then((payload) => {
        setAnalysis(payload);
        setSelectedPacketId(payload.candidates[0]?.packetId ?? 0);
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setAnalysis(EMPTY_ANALYSIS);
        setSelectedPacketId(0);
        setError(err instanceof Error ? err.message : "加载 Shiro rememberMe 分析失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [hasCapture, fileMeta.path]);

  const filteredCandidates = useMemo(() => {
    return analysis.candidates.filter((item) => {
      if (candidateFilter === "HIT") return (item.hitCount ?? 0) > 0;
      if (candidateFilter === "DELETEME") return (item.notes ?? []).some((note) => note.toLowerCase().includes("deleteme"));
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
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
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
        <div className="flex flex-wrap gap-2 rounded-xl border border-amber-100 bg-amber-50/50 p-4 text-[11px] shadow-sm">
          <MetaChip label="抓包" value={hasCapture ? fileMeta.name : "未加载"} color={hasCapture ? "sky" : "slate"} />
          <MetaChip label="候选" value={analysis.candidateCount} color="slate" />
          <MetaChip label="密钥命中" value={analysis.hitCount} color={analysis.hitCount > 0 ? "rose" : "slate"} />
          <MetaChip label="自定义 Key" value={keyLines.length} color={keyLines.length > 0 ? "sky" : "slate"} />
          {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
        </div>

        <div className="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)_auto]">
          <Field label="结果筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {(["ALL", "HIT", "DELETEME"] as CandidateFilter[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setCandidateFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    candidateFilter === item ? "bg-white text-amber-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {item === "ALL" ? "全部" : item === "HIT" ? "命中" : "deleteMe"}
                </button>
              ))}
            </div>
          </Field>
          <Field label="自定义 AES Key">
            <textarea
              value={customKeys}
              onChange={(event) => setCustomKeys(event.target.value)}
              rows={3}
              placeholder="每行一个 base64 key，支持 label::base64Key"
              className="min-h-[88px] w-full resize-y rounded-xl border border-slate-200 bg-white px-3.5 py-3 font-mono text-xs leading-relaxed text-slate-800 shadow-sm outline-none transition-all placeholder:text-slate-400 focus:border-amber-300 focus:ring-4 focus:ring-amber-100/70"
            />
          </Field>
          <div className="flex items-end gap-2">
            <Button type="button" variant="outline" onClick={() => void loadAnalysis()} disabled={!hasCapture || loading} className="gap-2 bg-white text-amber-700">
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "分析中..." : "刷新 / 测试 Key"}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <ExportButtons disabled={analysis.candidateCount === 0} onExport={exportAnalysis} />
        </div>

        {!error && <NotesList notes={analysis.notes} />}
        {error && <ErrorBlock message={error} />}

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.95fr)_minmax(0,1.05fr)]">
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-800">rememberMe 候选</div>
              <div className="text-[11px] text-slate-500">{filteredCandidates.length} 条</div>
            </div>
            <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
              {filteredCandidates.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
                  {hasCapture ? "当前筛选下没有 Shiro rememberMe 线索" : "未加载抓包"}
                </div>
              ) : (
                filteredCandidates.map((item) => {
                  const selected = selectedCandidate?.packetId === item.packetId;
                  return (
                    <button
                      key={`shiro-${item.packetId}-${item.cookieName}`}
                      type="button"
                      onClick={() => setSelectedPacketId(item.packetId)}
                      className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                        selected
                          ? "border-amber-400 bg-amber-50 shadow-sm ring-2 ring-amber-100"
                          : "border-slate-200 bg-white hover:border-amber-200 hover:bg-amber-50/40"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1 font-mono text-[11px] font-semibold text-amber-700">#{item.packetId}</span>
                        {item.hitCount ? (
                          <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">Key 命中</span>
                        ) : null}
                        {(item.notes ?? []).some((note) => note.toLowerCase().includes("deleteme")) ? (
                          <span className="rounded-md bg-slate-100 px-2 py-1 text-[11px] font-semibold text-slate-600">deleteMe</span>
                        ) : null}
                        <span className="text-[11px] text-slate-500">{item.sourceHeader || "Cookie"}</span>
                      </div>
                      <div className="mt-2 break-all font-medium text-slate-800">{renderCandidateTitle(item)}</div>
                      <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{item.cookiePreview || "--"}</div>
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
                  <div className="text-sm font-semibold text-slate-800">候选详情</div>
                  <div className="text-[12px] text-slate-500">查看 Cookie 来源、长度特征、AES 模式判断与候选密钥结果。</div>
                </div>
              </div>
              {!selectedCandidate ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                  请选择左侧的一条 rememberMe 候选。
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <MetaChip label="包号" value={selectedCandidate.packetId} color="slate" />
                    <MetaChip label="流" value={selectedCandidate.streamId ?? "--"} color="slate" />
                    <MetaChip label="Host" value={selectedCandidate.host || "--"} color="slate" />
                    <MetaChip label="Path" value={selectedCandidate.path || "/"} color="slate" />
                    <MetaChip label="长度" value={selectedCandidate.encryptedLength ?? "--"} color="slate" />
                    <MetaChip label="CBC" value={selectedCandidate.possibleCBC ? "可能" : "否"} color={selectedCandidate.possibleCBC ? "sky" : "slate"} />
                    <MetaChip label="GCM" value={selectedCandidate.possibleGCM ? "可能" : "否"} color={selectedCandidate.possibleGCM ? "sky" : "slate"} />
                  </div>
                  <EvidenceActions packetId={selectedCandidate.packetId} preferredProtocol="HTTP" />

                  <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
                    <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">Cookie Value</div>
                    <div className="break-all font-mono text-xs text-slate-700">{selectedCandidate.cookiePreview || "--"}</div>
                  </div>

                  <NotesList notes={selectedCandidate.notes} itemClassName="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600" />
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-3 flex items-center justify-between">
                <div className="text-sm font-semibold text-slate-800">密钥测试结果</div>
                <div className="text-[11px] text-slate-500">{selectedCandidate?.keyResults?.length ?? 0} 个 key</div>
              </div>
              <div className="space-y-2">
                {(selectedCandidate?.keyResults?.length ?? 0) === 0 ? (
                  <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                    暂无可展示的密钥测试结果。
                  </div>
                ) : (
                  selectedCandidate!.keyResults!.map((item) => (
                    <div key={`${item.label}-${item.base64}`} className={`rounded-xl border p-3 ${item.hit ? "border-rose-200 bg-rose-50/70" : "border-slate-200 bg-slate-50/70"}`}>
                      <div className="flex flex-wrap items-center gap-2">
                        {item.hit ? <ShieldAlert className="h-4 w-4 text-rose-600" /> : <ShieldCheck className="h-4 w-4 text-slate-400" />}
                        <span className="font-mono text-xs font-semibold text-slate-800">{item.label || "custom"}</span>
                        {item.algorithm ? <span className="rounded bg-white px-2 py-0.5 text-[11px] text-slate-600">{item.algorithm}</span> : null}
                        {item.hit ? <span className="rounded bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-700">命中 Java 序列化</span> : null}
                      </div>
                      {item.payloadClass ? <div className="mt-2 break-all text-xs text-slate-700">Payload: {item.payloadClass}</div> : null}
                      {item.preview ? <div className="mt-2 break-all font-mono text-[11px] text-slate-600">{item.preview}</div> : null}
                      {!item.hit && item.reason ? <div className="mt-2 break-all text-[11px] text-slate-500">{item.reason}</div> : null}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
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
    lines.push(`  来源: ${candidate.sourceHeader || "Cookie"} / stream=${candidate.streamId ?? "--"} / hit=${candidate.hitCount ?? 0}`);
    if ((candidate.notes?.length ?? 0) > 0) {
      lines.push(`  备注: ${candidate.notes!.join("; ")}`);
    }
    for (const result of candidate.keyResults ?? []) {
      lines.push(`  Key ${result.label}: ${result.hit ? "HIT" : "MISS"} ${result.algorithm || ""} ${result.payloadClass || result.reason || ""}`.trim());
    }
  }
  return lines.join("\n");
}
