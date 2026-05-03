import { Copy, KeyRound, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { NTLMSessionMaterial } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { ErrorBlock, ExportButtons, Field, MetaChip } from "../ui";
import { copyTextToClipboard } from "../../utils/browserFile";

type ProtocolFilter = "ALL" | "HTTP" | "WinRM" | "SMB3" | "NTLM";

export function NTLMSessionMaterialsModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [materials, setMaterials] = useState<NTLMSessionMaterial[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedFrame, setSelectedFrame] = useState("");
  const [copyNotice, setCopyNotice] = useState("");
  const embedded = surfaceVariant === "embedded";

  async function loadMaterials() {
    if (!hasCapture) {
      setMaterials([]);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const rows = await bridge.listNTLMSessionMaterials();
      setMaterials(rows);
      setSelectedFrame((current) => current && rows.some((item) => item.frameNumber === current) ? current : rows[0]?.frameNumber ?? "");
    } catch (err) {
      setMaterials([]);
      setSelectedFrame("");
      setError(err instanceof Error ? err.message : "加载 NTLM 会话材料失败");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let disposed = false;
    if (!hasCapture) {
      setMaterials([]);
      setSelectedFrame("");
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    void bridge.listNTLMSessionMaterials()
      .then((rows) => {
        if (disposed) return;
        setMaterials(rows);
        setSelectedFrame(rows[0]?.frameNumber ?? "");
      })
      .catch((err) => {
        if (disposed) return;
        setMaterials([]);
        setSelectedFrame("");
        setError(err instanceof Error ? err.message : "加载 NTLM 会话材料失败");
      })
      .finally(() => {
        if (!disposed) {
          setLoading(false);
        }
      });
    return () => {
      disposed = true;
    };
  }, [hasCapture, fileMeta.path]);

  const filtered = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    return materials.filter((item) => {
      if (protocolFilter !== "ALL" && item.protocol !== protocolFilter) {
        return false;
      }
      if (!keyword) {
        return true;
      }
      const haystack = [
        item.displayLabel,
        item.protocol,
        item.transport,
        item.userDisplay,
        item.username,
        item.domain,
        item.src,
        item.dst,
        item.challenge,
        item.ntProofStr,
        item.encryptedSessionKey,
        item.sessionId,
        item.info,
      ].join(" ").toLowerCase();
      return haystack.includes(keyword);
    });
  }, [materials, protocolFilter, query]);

  const selected = useMemo(
    () => filtered.find((item) => item.frameNumber === selectedFrame) ?? filtered[0] ?? null,
    [filtered, selectedFrame],
  );

  const completeCount = useMemo(() => materials.filter((item) => item.complete).length, [materials]);

  async function copySelectedMaterial() {
    if (!selected) return;
    const text = renderMaterialText(selected);
    if (await copyTextToClipboard(text)) {
      setCopyNotice(`已复制帧 #${selected.frameNumber} 的 NTLM 材料`);
    } else {
      setCopyNotice("复制失败");
    }
    window.setTimeout(() => setCopyNotice(""), 1800);
  }

  function exportMaterials(format: MiscExportFormat) {
    const rows = filtered;
    exportStructuredResult({
      filenameBase: "ntlm-session-materials",
      format,
      payload: rows,
      renderText: renderMaterialsText,
    });
  }

  return (
    <Card className={embedded ? "min-w-0 h-fit border-0 bg-transparent shadow-none" : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"}>
      <CardHeader className={embedded ? "hidden" : "gap-2 border-b border-slate-100 bg-slate-50/70 pb-5"}>
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-100 text-violet-600">
            <KeyRound className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
        <div className="flex flex-wrap gap-2 rounded-xl border border-violet-100 bg-violet-50/50 p-4 text-[11px] shadow-sm">
          <MetaChip label="抓包" value={hasCapture ? fileMeta.name : "未加载"} color={hasCapture ? "sky" : "slate"} />
          <MetaChip label="总材料" value={materials.length} color="slate" />
          <MetaChip label="完整" value={completeCount} color="emerald" />
          <MetaChip label="缺字段" value={Math.max(0, materials.length - completeCount)} color={completeCount === materials.length ? "slate" : "rose"} />
          {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
        </div>

        <div className="grid gap-4 md:grid-cols-[180px_minmax(0,1fr)_auto]">
          <Field label="协议筛选">
            <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
              {(["ALL", "HTTP", "WinRM", "SMB3", "NTLM"] as ProtocolFilter[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setProtocolFilter(item)}
                  className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                    protocolFilter === item ? "bg-white text-violet-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {item === "ALL" ? "全部" : item}
                </button>
              ))}
            </div>
          </Field>
          <Field label="检索材料">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="font-mono text-sm shadow-sm"
              placeholder="用户名 / challenge / NTProofStr / IP / session id"
            />
          </Field>
          <div className="flex items-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => void loadMaterials()}
              disabled={!hasCapture || loading}
              className="gap-2 border-violet-200 bg-white text-violet-700 hover:bg-violet-50"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "扫描中..." : "刷新"}
            </Button>
          </div>
        </div>

        {!error && (
          <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
            {hasCapture
              ? (loading
                ? "正在从当前抓包提取 NTLM 会话材料..."
                : `当前筛选命中 ${filtered.length} 条材料，可统一查看 HTTP / WinRM / SMB3 的 NTLM challenge 与 session key。`)
              : "未加载抓包，请先在主工作区导入文件"}
          </div>
        )}
        {error && <ErrorBlock message={error} />}

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.95fr)_minmax(0,1.05fr)]">
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-slate-800">会话材料列表</div>
              <div className="text-[11px] text-slate-500">{filtered.length} 条</div>
            </div>
            <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
              {filtered.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
                  {hasCapture ? "当前筛选下没有匹配的 NTLM 会话材料" : "未加载抓包"}
                </div>
              ) : (
                filtered.map((item) => {
                  const selectedRow = selected?.frameNumber === item.frameNumber;
                  return (
                    <button
                      key={`${item.frameNumber}-${item.protocol}-${item.displayLabel}`}
                      type="button"
                      onClick={() => setSelectedFrame(item.frameNumber)}
                      className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                        selectedRow
                          ? "border-violet-400 bg-violet-50 shadow-sm ring-2 ring-violet-100"
                          : "border-slate-200 bg-white hover:border-violet-200 hover:bg-violet-50/40"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-md border border-violet-200 bg-violet-50 px-2 py-1 font-mono text-[11px] font-semibold text-violet-700">{item.protocol}</span>
                        <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${item.complete ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"}`}>
                          {item.complete ? "材料完整" : "待补字段"}
                        </span>
                        <span className="text-[11px] text-slate-500">帧 #{item.frameNumber}</span>
                        {item.transport && <span className="text-[11px] text-slate-500">{item.transport}</span>}
                      </div>
                      <div className="mt-2 font-medium text-slate-800">{item.userDisplay || item.displayLabel}</div>
                      <div className="mt-1 break-all font-mono text-[12px] text-slate-600">
                        {(item.src || "?") + " -> " + (item.dst || "?")}
                      </div>
                      {item.info && <div className="mt-1 line-clamp-2 text-[12px] text-slate-500">{item.info}</div>}
                    </button>
                  );
                })
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-sm font-semibold text-slate-800">材料详情</div>
                <div className="text-[12px] text-slate-500">统一查看 challenge、NT proof、session key、方向和认证头。</div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <ExportButtons disabled={filtered.length === 0} onExport={exportMaterials} />
                <Button variant="outline" onClick={() => void copySelectedMaterial()} disabled={!selected} className="gap-2 bg-white text-slate-700">
                  <Copy className="h-4 w-4 text-violet-600" />
                  复制当前
                </Button>
              </div>
            </div>

            {copyNotice && (
              <div className="mb-3 rounded-md border border-violet-200 bg-violet-50 px-3 py-2 text-xs text-violet-700">{copyNotice}</div>
            )}

            {!selected ? (
              <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
                请选择左侧的一条 NTLM 材料查看详情。
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap gap-2">
                  <MetaChip label="协议" value={selected.protocol} color="sky" />
                  <MetaChip label="方向" value={selected.direction || "--"} color="slate" />
                  <MetaChip label="包号" value={`#${selected.frameNumber}`} color="slate" />
                  <MetaChip label="完整度" value={selected.complete ? "完整" : "待补"} color={selected.complete ? "emerald" : "rose"} />
                  {selected.sessionId && <MetaChip label="Session" value={selected.sessionId} color="slate" />}
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <MaterialField label="用户名" value={selected.userDisplay || selected.username} mono />
                  <MaterialField label="域" value={selected.domain} mono />
                  <MaterialField label="源地址" value={selected.src ? `${selected.src}${selected.srcPort ? `:${selected.srcPort}` : ""}` : undefined} mono />
                  <MaterialField label="目标地址" value={selected.dst ? `${selected.dst}${selected.dstPort ? `:${selected.dstPort}` : ""}` : undefined} mono />
                  <MaterialField label="时间" value={selected.timestamp} mono />
                  <MaterialField label="传输标签" value={selected.transport} mono />
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <MaterialField label="Challenge" value={selected.challenge} mono multiline />
                  <MaterialField label="NTProofStr" value={selected.ntProofStr} mono multiline />
                  <MaterialField label="Encrypted Session Key" value={selected.encryptedSessionKey} mono multiline />
                  <MaterialField label="摘要 / Info" value={selected.info} multiline />
                </div>

                {(selected.authHeader || selected.wwwAuthenticate) && (
                  <div className="grid gap-4 md:grid-cols-2">
                    <MaterialField label="Authorization" value={selected.authHeader} mono multiline />
                    <MaterialField label="WWW-Authenticate" value={selected.wwwAuthenticate} mono multiline />
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MaterialField({
  label,
  value,
  mono = false,
  multiline = false,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  multiline?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className={`break-all text-[13px] text-slate-800 ${mono ? "font-mono" : ""} ${multiline ? "whitespace-pre-wrap" : ""}`}>
        {value || "--"}
      </div>
    </div>
  );
}

function renderMaterialText(item: NTLMSessionMaterial) {
  return [
    `Display: ${item.displayLabel}`,
    `Protocol: ${item.protocol}`,
    `Direction: ${item.direction || ""}`,
    `Frame: ${item.frameNumber}`,
    `Timestamp: ${item.timestamp || ""}`,
    `Transport: ${item.transport || ""}`,
    `Source: ${item.src || ""}${item.srcPort ? `:${item.srcPort}` : ""}`,
    `Destination: ${item.dst || ""}${item.dstPort ? `:${item.dstPort}` : ""}`,
    `User: ${item.userDisplay || item.username || ""}`,
    `Domain: ${item.domain || ""}`,
    `Challenge: ${item.challenge || ""}`,
    `NTProofStr: ${item.ntProofStr || ""}`,
    `EncryptedSessionKey: ${item.encryptedSessionKey || ""}`,
    `SessionID: ${item.sessionId || ""}`,
    `Authorization: ${item.authHeader || ""}`,
    `WWW-Authenticate: ${item.wwwAuthenticate || ""}`,
    `Info: ${item.info || ""}`,
    `Complete: ${item.complete ? "true" : "false"}`,
  ].join("\n");
}

function renderMaterialsText(rows: NTLMSessionMaterial[]) {
  return rows.map(renderMaterialText).join("\n\n" + "-".repeat(80) + "\n\n");
}
