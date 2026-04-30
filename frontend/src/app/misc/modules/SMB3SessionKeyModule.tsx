import { Copy, Key, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { SMB3RandomSessionKeyResult, SMB3SessionCandidate } from "../../core/types";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { ErrorBlock, Field } from "../ui";

export function SMB3SessionKeyModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const [smbUser, setSmbUser] = useState("");
  const [smbDomain, setSmbDomain] = useState("");
  const [smbHash, setSmbHash] = useState("");
  const [smbProof, setSmbProof] = useState("");
  const [smbKey, setSmbKey] = useState("");
  const [smbCandidates, setSmbCandidates] = useState<SMB3SessionCandidate[]>([]);
  const [smbCandidatesLoading, setSmbCandidatesLoading] = useState(false);
  const [smbCandidatesError, setSmbCandidatesError] = useState("");
  const [smbSelectedCandidateFrame, setSmbSelectedCandidateFrame] = useState("");
  const [smbLoading, setSmbLoading] = useState(false);
  const [smbError, setSmbError] = useState("");
  const [smbResult, setSmbResult] = useState<SMB3RandomSessionKeyResult | null>(null);
  const embedded = surfaceVariant === "embedded";

  const hasCapture = Boolean(fileMeta.path);
  const smbCandidateSummary = useMemo(() => {
    if (smbCandidatesLoading) return "正在扫描当前抓包中的 SMB3 Session 候选...";
    if (!hasCapture) return "未加载抓包，请先在主工作区导入文件";
    if (smbCandidatesError) return "";
    if (smbCandidates.length === 0) return "未在当前抓包中发现可用的 SMB3 Session 候选";
    const completeCount = smbCandidates.filter((candidate) => candidate.complete).length;
    return `已发现 ${smbCandidates.length} 条候选，其中 ${completeCount} 条材料完整`;
  }, [hasCapture, smbCandidates, smbCandidatesError, smbCandidatesLoading]);

  async function fetchSMB3Candidates() {
    if (!hasCapture) {
      setSmbCandidates([]);
      setSmbCandidatesLoading(false);
      setSmbCandidatesError("");
      setSmbSelectedCandidateFrame("");
      return;
    }
    setSmbCandidatesLoading(true);
    setSmbCandidatesError("");
    try {
      const rows = await bridge.listSMB3SessionCandidates();
      setSmbCandidates(rows);
      setSmbSelectedCandidateFrame("");
    } catch (error) {
      setSmbCandidates([]);
      setSmbSelectedCandidateFrame("");
      setSmbCandidatesError(error instanceof Error ? error.message : "加载 SMB3 Session 候选失败");
    } finally {
      setSmbCandidatesLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadSMB3Candidates() {
      try {
        if (!hasCapture) {
          setSmbCandidates([]);
          setSmbCandidatesLoading(false);
          setSmbCandidatesError("");
          setSmbSelectedCandidateFrame("");
          return;
        }
        setSmbCandidatesLoading(true);
        setSmbCandidatesError("");
        const rows = await bridge.listSMB3SessionCandidates();
        if (cancelled) return;
        setSmbCandidates(rows);
        setSmbSelectedCandidateFrame("");
      } catch (error) {
        if (cancelled) return;
        setSmbCandidates([]);
        setSmbSelectedCandidateFrame("");
        setSmbCandidatesError(error instanceof Error ? error.message : "加载 SMB3 Session 候选失败");
      } finally {
        if (!cancelled) {
          setSmbCandidatesLoading(false);
        }
      }
    }

    void loadSMB3Candidates();
    return () => {
      cancelled = true;
    };
  }, [hasCapture, fileMeta.path]);

  async function runSMB() {
    setSmbLoading(true);
    setSmbError("");
    try {
      const result = await bridge.generateSMB3RandomSessionKey({
        username: smbUser,
        domain: smbDomain,
        ntlmHash: smbHash,
        ntProofStr: smbProof,
        encryptedSessionKey: smbKey,
      });
      setSmbResult(result);
    } catch (error) {
      setSmbError(error instanceof Error ? error.message : "SMB3 Session Key 生成失败");
      setSmbResult(null);
    } finally {
      setSmbLoading(false);
    }
  }

  async function copySMBResult() {
    if (!smbResult?.randomSessionKey) return;
    try {
      await navigator.clipboard.writeText(smbResult.randomSessionKey);
    } catch {
      // ignore
    }
  }

  async function refreshSMB3Candidates() {
    if (!hasCapture) {
      setSmbCandidates([]);
      setSmbCandidatesError("请先在主工作区导入抓包文件");
      return;
    }
    await fetchSMB3Candidates();
  }

  function applySMB3Candidate(frameNumber: string) {
    setSmbSelectedCandidateFrame(frameNumber);
    const candidate = smbCandidates.find((item) => item.frameNumber === frameNumber);
    if (!candidate) return;
    setSmbUser(candidate.username);
    setSmbDomain(candidate.domain);
    setSmbProof(candidate.ntProofStr);
    setSmbKey(candidate.encryptedSessionKey);
    setSmbResult(null);
    setSmbError("");
  }

  return (
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
      <CardHeader className={embedded ? "hidden" : "gap-2 border-b border-slate-100 bg-slate-50/70 pb-5"}>
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600">
            <Key className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-6 px-0 pt-0" : "space-y-6 pt-6"}>
        <div className="grid gap-4">
          <Field label="Session 候选选择器">
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3 rounded-xl border border-indigo-100 bg-indigo-50/50 px-3 py-2.5">
                <div className="min-w-0">
                  <div className="text-[12px] font-semibold uppercase tracking-[0.18em] text-indigo-500">Session 候选</div>
                  <div className="mt-1 text-[13px] text-slate-600">
                    {smbCandidatesLoading
                      ? "正在扫描当前抓包中的 SMB3 Session 候选..."
                      : smbCandidates.length > 0
                        ? "点击候选卡片后自动回填除哈希外的字段"
                        : "暂无可选候选"}
                  </div>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  data-testid="smb-session-candidate-refresh"
                  onClick={() => void refreshSMB3Candidates()}
                  disabled={!hasCapture || smbCandidatesLoading}
                  className="shrink-0 border-indigo-200 bg-white text-indigo-700 hover:bg-indigo-50"
                >
                  刷新候选
                </Button>
              </div>

              <div
                data-testid="smb-session-candidate-select"
                aria-disabled={!hasCapture || smbCandidatesLoading || smbCandidates.length === 0}
                className={`rounded-xl border p-3 transition-colors ${
                  !hasCapture || smbCandidates.length === 0 ? "border-slate-200 bg-slate-50" : "border-indigo-100 bg-white"
                }`}
              >
                {smbCandidates.length > 0 ? (
                  <div className="grid max-h-64 gap-2 overflow-auto pr-1">
                    {smbCandidates.map((candidate) => {
                      const selected = smbSelectedCandidateFrame === candidate.frameNumber;
                      const sessionLabel = candidate.sessionId || "未知 SessionId";
                      const userLabel = candidate.domain ? `${candidate.domain}\\${candidate.username || "未知用户"}` : candidate.username || "未知用户";
                      return (
                        <button
                          key={`${candidate.frameNumber}-${candidate.sessionId || "unknown"}`}
                          type="button"
                          data-testid={`smb-session-candidate-${candidate.frameNumber}`}
                          onClick={() => applySMB3Candidate(candidate.frameNumber)}
                          className={`rounded-xl border px-3 py-3 text-left transition-all ${
                            selected
                              ? "border-indigo-400 bg-indigo-50 shadow-sm ring-2 ring-indigo-100"
                              : "border-slate-200 bg-slate-50/70 hover:border-indigo-200 hover:bg-indigo-50/40"
                          }`}
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded-md border border-indigo-200 bg-indigo-50 px-2 py-1 font-mono text-[11px] font-semibold text-indigo-700">{sessionLabel}</span>
                            <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${candidate.complete ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"}`}>
                              {candidate.complete ? "材料完整" : "待补字段"}
                            </span>
                            <span className="text-[11px] text-slate-500">帧 #{candidate.frameNumber}</span>
                            {candidate.timestamp && <span className="text-[11px] text-slate-500">{candidate.timestamp}</span>}
                          </div>
                          <div className="mt-2 text-[13px] font-semibold text-slate-800">{userLabel}</div>
                          <div className="mt-1 break-all font-mono text-[12px] text-slate-600">
                            {candidate.src || "?"} {"->"} {candidate.dst || "?"}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                ) : (
                  <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-6 text-center text-[13px] text-slate-500">
                    {hasCapture ? "未在当前抓包中发现可用的 SMB3 Session 候选" : "未加载抓包，请先在主工作区导入文件"}
                  </div>
                )}
              </div>
            </div>
          </Field>
          {!smbCandidatesError && <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">{smbCandidateSummary}</div>}
          {smbCandidatesError && <ErrorBlock message={smbCandidatesError} />}
          <Field label="Username (用户名)">
            <Input value={smbUser} onChange={(event) => setSmbUser(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="Administrator" />
          </Field>
          <Field label="Domain (域名/可留空)">
            <Input value={smbDomain} onChange={(event) => setSmbDomain(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="WORKGROUP 或留空" />
          </Field>
          <Field label="NTLM Hash (十六进制)">
            <Input value={smbHash} onChange={(event) => setSmbHash(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="例如: 31d...89c0" />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="NTProofStr">
              <Input value={smbProof} onChange={(event) => setSmbProof(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="..." />
            </Field>
            <Field label="Encrypted Session Key">
              <Input value={smbKey} onChange={(event) => setSmbKey(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="..." />
            </Field>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <Button onClick={() => void runSMB()} disabled={smbLoading} className="gap-2 bg-indigo-600 text-white shadow-sm hover:bg-indigo-700">
            <Key className="h-4 w-4" />
            {smbLoading ? "计算中..." : "生成 Session Key"}
          </Button>

          {smbResult && (
            <>
              <div className="mx-1 h-6 w-px bg-slate-200" />
              <Button variant="outline" onClick={() => void copySMBResult()} disabled={!smbResult?.randomSessionKey} className="gap-2 text-slate-700 shadow-sm">
                <Copy className="h-4 w-4 text-blue-600" />
                复制十六进制 Key
              </Button>
              <Button variant="ghost" onClick={() => { setSmbResult(null); setSmbError(""); }} className="gap-2 text-rose-600 hover:bg-rose-50 hover:text-rose-700">
                <Trash2 className="h-4 w-4" />
                清空
              </Button>
            </>
          )}
        </div>

        {smbError && <div className="animate-in slide-in-from-bottom-2 duration-300 fade-in"><ErrorBlock message={smbError} /></div>}
        {smbResult && (
          <div className="mt-4 animate-in slide-in-from-bottom-2 duration-300 fade-in rounded-xl border border-indigo-100 bg-indigo-50/50 p-5 shadow-sm">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-900">
                <Key className="h-3.5 w-3.5 text-indigo-500" />
                最终 Random Session Key
              </div>
            </div>
            <pre className="whitespace-pre-wrap break-all rounded-lg border border-indigo-200/60 bg-white p-3 font-mono text-[13px] font-semibold leading-relaxed text-indigo-700 shadow-sm selection:bg-indigo-100">
              {smbResult.randomSessionKey}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
