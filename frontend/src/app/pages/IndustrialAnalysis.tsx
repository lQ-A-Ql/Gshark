import { AlertTriangle, Factory, RefreshCw, Shield, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { IndustrialAnalysis as IndustrialAnalysisData, TrafficBucket } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

const EMPTY_ANALYSIS: IndustrialAnalysisData = {
  totalIndustrialPackets: 0,
  protocols: [],
  conversations: [],
  modbus: {
    totalFrames: 0,
    requests: 0,
    responses: 0,
    exceptions: 0,
    functionCodes: [],
    unitIds: [],
    referenceHits: [],
    exceptionCodes: [],
    transactions: [],
  },
  details: [],
  notes: [],
};

const industrialAnalysisCache = new Map<string, IndustrialAnalysisData>();

export default function IndustrialAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets } = useSentinel();
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${fileMeta.path}::${totalPackets}`;
  }, [fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<IndustrialAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_ANALYSIS);
      return;
    }
    if (!force && cacheKey && industrialAnalysisCache.has(cacheKey)) {
      setAnalysis(industrialAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    void bridge
      .getIndustrialAnalysis()
      .then((payload) => {
        if (cacheKey) {
          industrialAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "工控分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [backendConnected, cacheKey]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-lg font-semibold">
        <Factory className="h-5 w-5 text-blue-600" />
        工控分析
        <span className="rounded border border-border bg-accent px-2 py-0.5 text-xs font-medium text-muted-foreground">Modbus / S7 / DNP3 / CIP / BACnet / IEC104 / OPC UA / PROFINET</span>
        <button
          className="ml-2 inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => refreshAnalysis(true)}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </button>
      </div>

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在调用 tshark 生成工控分析结果...</div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="工控相关包" value={analysis.totalIndustrialPackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="Modbus 帧" value={analysis.modbus.totalFrames.toLocaleString()} />
        <StatCard title="异常响应" value={analysis.modbus.exceptions.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="工控协议分布">
          <BucketChart data={analysis.protocols} color="bg-blue-500" />
        </Panel>
        <Panel title="工控会话">
          <ConversationList
            items={analysis.conversations.map((item) => ({
              label: item.protocol ? `${item.protocol} · ${item.label}` : item.label,
              count: item.count,
            }))}
          />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="Modbus 请求" value={analysis.modbus.requests.toLocaleString()} />
        <StatCard title="Modbus 响应" value={analysis.modbus.responses.toLocaleString()} />
        <StatCard title="功能码种类" value={String(analysis.modbus.functionCodes.length)} />
        <StatCard title="目标 Unit 数" value={String(analysis.modbus.unitIds.length)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Modbus 功能码">
          <BucketChart data={analysis.modbus.functionCodes} color="bg-indigo-500" />
        </Panel>
        <Panel title="Modbus Unit ID">
          <BucketChart data={analysis.modbus.unitIds} color="bg-cyan-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="寄存器 / 线圈引用">
          <BucketChart data={analysis.modbus.referenceHits} color="bg-emerald-500" />
        </Panel>
        <Panel title="异常码">
          <BucketChart data={analysis.modbus.exceptionCodes} color="bg-rose-500" />
        </Panel>
      </div>

      <Panel title="分析提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.notes.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到工控协议。</div>
          ) : (
            analysis.notes.map((note, index) => (
              <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
                <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                <span>{note}</span>
              </div>
            ))
          )}
        </div>
      </Panel>

      {(analysis.suspiciousWrites?.length ?? 0) > 0 && (
        <Panel title={`Modbus 可疑写操作 (${analysis.suspiciousWrites!.length})`} className="mt-4">
          <div className="mb-2 flex items-start gap-2 rounded border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-700">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>以下为按写入次数排序的 Modbus 写操作聚合，高频写入可能对应灯控、阀门切换或寄存器篡改。</span>
          </div>
          <div className="max-h-[420px] overflow-auto">
            <table className="w-full table-fixed border-collapse text-left text-xs">
              <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
                <tr>
                  <th className="w-36 px-3 py-2">目标地址</th>
                  <th className="w-20 px-3 py-2">Unit ID</th>
                  <th className="w-28 px-3 py-2">功能码</th>
                  <th className="w-20 px-3 py-2">写入次数</th>
                  <th className="w-36 px-3 py-2">来源 IP</th>
                  <th className="w-28 px-3 py-2">首次时间</th>
                  <th className="w-28 px-3 py-2">末次时间</th>
                  <th className="px-3 py-2">样本值</th>
                </tr>
              </thead>
              <tbody>
                {analysis.suspiciousWrites!.map((sw, idx) => (
                  <tr key={`sw-${idx}`} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2 font-mono">{sw.target}</td>
                    <td className="px-3 py-2 font-mono">{sw.unitId || "--"}</td>
                    <td className="px-3 py-2">
                      <div className="font-mono">{String(sw.functionCode).padStart(2, "0")}</div>
                      <div className="text-muted-foreground">{sw.functionName}</div>
                    </td>
                    <td className="px-3 py-2 font-mono font-semibold text-amber-700">{sw.writeCount}</td>
                    <td className="px-3 py-2 font-mono">{sw.sources.join(", ") || "--"}</td>
                    <td className="px-3 py-2 font-mono">{sw.firstTime || "--"}</td>
                    <td className="px-3 py-2 font-mono">{sw.lastTime || "--"}</td>
                    <td className="px-3 py-2">
                      {sw.sampleValues.length > 0 ? (
                        <div className="space-y-0.5">
                          {sw.sampleValues.map((v, vi) => (
                            <div key={vi} className="break-all font-mono text-[11px] text-muted-foreground">{v}</div>
                          ))}
                        </div>
                      ) : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {(analysis.controlCommands?.length ?? 0) > 0 && (
        <Panel title={`控制指令 (${analysis.controlCommands!.length})`} className="mt-4">
          <div className="mb-2 flex items-start gap-2 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
            <Shield className="mt-0.5 h-4 w-4 shrink-0" />
            <span>以下为从 IEC 104、DNP3、BACnet 等协议中提取的控制/操作类指令，可能涉及遥控、设点或设备重启。</span>
          </div>
          <div className="max-h-[520px] overflow-auto">
            <table className="w-full table-fixed border-collapse text-left text-xs">
              <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
                <tr>
                  <th className="w-20 px-3 py-2">包号</th>
                  <th className="w-28 px-3 py-2">时间</th>
                  <th className="w-20 px-3 py-2">协议</th>
                  <th className="w-32 px-3 py-2">源</th>
                  <th className="w-32 px-3 py-2">目标</th>
                  <th className="w-36 px-3 py-2">操作</th>
                  <th className="w-28 px-3 py-2">对象</th>
                  <th className="w-24 px-3 py-2">值</th>
                  <th className="w-24 px-3 py-2">结果</th>
                  <th className="px-3 py-2">摘要</th>
                </tr>
              </thead>
              <tbody>
                {analysis.controlCommands!.map((cmd, idx) => (
                  <tr key={`cmd-${idx}`} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2 font-mono text-muted-foreground">{cmd.packetId}</td>
                    <td className="px-3 py-2 font-mono">{cmd.time || "--"}</td>
                    <td className="px-3 py-2">
                      <span className="rounded border border-blue-200 bg-blue-50 px-1.5 py-0.5 text-blue-700">{cmd.protocol}</span>
                    </td>
                    <td className="px-3 py-2">{cmd.source || "--"}</td>
                    <td className="px-3 py-2">{cmd.destination || "--"}</td>
                    <td className="px-3 py-2 font-mono font-semibold text-rose-700">{cmd.operation || "--"}</td>
                    <td className="px-3 py-2 font-mono">{cmd.target || "--"}</td>
                    <td className="px-3 py-2 font-mono">{cmd.value || "--"}</td>
                    <td className="px-3 py-2">{cmd.result || "--"}</td>
                    <td className="px-3 py-2">{cmd.summary || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel title={`Modbus 事务明细 (${analysis.modbus.transactions.length})`} className="mt-4">
        <div className="max-h-[520px] overflow-auto">
          <table className="w-full table-fixed border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
              <tr>
                <th className="w-20 px-3 py-2">包号</th>
                <th className="w-28 px-3 py-2">时间</th>
                <th className="w-40 px-3 py-2">源</th>
                <th className="w-40 px-3 py-2">目标</th>
                <th className="w-28 px-3 py-2">功能码</th>
                <th className="w-20 px-3 py-2">类型</th>
                <th className="w-24 px-3 py-2">Unit</th>
                <th className="w-28 px-3 py-2">引用</th>
                <th className="w-20 px-3 py-2">数量</th>
                <th className="w-20 px-3 py-2">耗时</th>
                <th className="px-3 py-2">摘要</th>
              </tr>
            </thead>
            <tbody>
              {analysis.modbus.transactions.length === 0 ? (
                <tr>
                  <td colSpan={11} className="px-3 py-6 text-center text-muted-foreground">暂无 Modbus 事务</td>
                </tr>
              ) : (
                analysis.modbus.transactions.map((item) => (
                  <tr key={`${item.packetId}-${item.transactionId}-${item.kind}`} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2 font-mono text-muted-foreground">{item.packetId}</td>
                    <td className="px-3 py-2 font-mono">{item.time || "--"}</td>
                    <td className="px-3 py-2">{item.source || "--"}</td>
                    <td className="px-3 py-2">{item.destination || "--"}</td>
                    <td className="px-3 py-2">
                      <div className="font-mono">{item.functionCode || "--"}</div>
                      <div className="text-muted-foreground">{item.functionName || "--"}</div>
                    </td>
                    <td className="px-3 py-2">
                      <span className={kindBadge(item.kind)}>{item.kind}</span>
                    </td>
                    <td className="px-3 py-2 font-mono">{item.unitId || "--"}</td>
                    <td className="px-3 py-2 font-mono">{item.reference || "--"}</td>
                    <td className="px-3 py-2 font-mono">{item.quantity || "--"}</td>
                    <td className="px-3 py-2 font-mono">{item.responseTime || "--"}</td>
                    <td className="px-3 py-2">
                      <div>{item.summary || "--"}</div>
                      {item.bitRange?.preview && (
                        <div className="mt-1 break-all font-mono text-[11px] text-blue-700">
                          位值解析: {item.bitRange.preview}
                        </div>
                      )}
                      {item.registerValues && <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.registerValues}</div>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {analysis.details.map((detail) => (
        <Panel key={detail.name} title={`${detail.name} 明细 (${detail.records.length})`} className="mt-4">
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatCard title="总帧数" value={detail.totalFrames.toLocaleString()} />
            <StatCard title="操作类型" value={String(detail.operations.length)} />
            <StatCard title="目标对象" value={String(detail.targets.length)} />
            <StatCard title="结果项" value={String(detail.results.length)} />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Panel title="操作分布">
              <BucketChart data={detail.operations} color="bg-blue-500" />
            </Panel>
            <Panel title="目标对象">
              <BucketChart data={detail.targets} color="bg-emerald-500" />
            </Panel>
            <Panel title="结果 / 状态">
              <BucketChart data={detail.results} color="bg-amber-500" />
            </Panel>
          </div>
          <div className="mt-4">
            <DataTable
              headers={["包号", "时间", "源", "目标", "操作", "对象", "结果", "值", "摘要"]}
              rows={detail.records.map((item) => [
                item.packetId,
                item.time || "--",
                item.source || "--",
                item.destination || "--",
                item.operation || "--",
                item.target || "--",
                item.result || "--",
                item.value || "--",
                item.summary || "--",
              ])}
            />
          </div>
        </Panel>
      ))}
    </div>
  );
}

function kindBadge(kind: string) {
  switch (kind) {
    case "request":
      return "rounded border border-blue-200 bg-blue-50 px-2 py-0.5 text-blue-700";
    case "response":
      return "rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-emerald-700";
    default:
      return "rounded border border-rose-200 bg-rose-50 px-2 py-0.5 text-rose-700";
  }
}

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-2 text-xs text-muted-foreground">{title}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-border bg-card p-4 shadow-sm ${className}`.trim()}>
      <div className="mb-3 text-sm font-semibold">{title}</div>
      {children}
    </div>
  );
}

function BucketChart({ data, color }: { data: TrafficBucket[]; color: string }) {
  const max = Math.max(1, ...data.map((item) => item.count));
  if (data.length === 0) {
    return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">暂无数据</div>;
  }
  return (
    <div className="max-h-[420px] overflow-auto pr-1">
      <div className="space-y-2">
        {data.map((row) => (
          <div key={row.label} className="grid grid-cols-[220px_1fr_72px] items-center gap-2 text-xs">
            <div className="truncate text-muted-foreground" title={row.label}>{row.label}</div>
            <div className="h-2 rounded bg-accent">
              <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono">{row.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConversationList({ items }: { items: TrafficBucket[] }) {
  if (items.length === 0) {
    return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">暂无数据</div>;
  }
  return (
    <div className="max-h-[420px] space-y-2 overflow-auto pr-1">
      {items.map((item) => (
        <div key={`${item.label}-${item.count}`} className="flex items-center justify-between rounded border border-border bg-background px-3 py-2 text-xs">
          <span className="truncate text-muted-foreground" title={item.label}>{item.label}</span>
          <span className="ml-3 font-mono text-foreground">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

function DataTable({ headers, rows }: { headers: string[]; rows: Array<Array<string | number>> }) {
  return (
    <div className="max-h-[420px] overflow-auto">
      <table className="w-full table-fixed border-collapse text-left text-xs">
        <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
          <tr>
            {headers.map((header) => (
              <th key={header} className="px-3 py-2">{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={headers.length} className="px-3 py-6 text-center text-muted-foreground">暂无数据</td>
            </tr>
          ) : (
            rows.map((row, rowIndex) => (
              <tr key={rowIndex} className="border-b border-border/70 align-top">
                {row.map((value, cellIndex) => (
                  <td key={`${rowIndex}-${cellIndex}`} className="px-3 py-2">{String(value)}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
