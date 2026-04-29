import { AlertTriangle, Factory, Shield, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { IndustrialAnalysis as IndustrialAnalysisData } from "../core/types";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBadge,
  AnalysisBucketChart as BucketChart,
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisList as ConversationList,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
  type AnalysisTone,
} from "../components/analysis/AnalysisPrimitives";
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
  ruleHits: [],
  details: [],
  notes: [],
};

const industrialAnalysisCache = new Map<string, IndustrialAnalysisData>();

const INDUSTRIAL_PROTOCOL_TAGS = [
  "Modbus",
  "S7",
  "DNP3",
  "CIP",
  "BACnet",
  "IEC104",
  "OPC UA",
  "PROFINET",
];

export default function IndustrialAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const cacheKey = useMemo(() => {
    return buildIndustrialAnalysisCacheKey(captureRevision, fileMeta.path, totalPackets);
  }, [captureRevision, fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<IndustrialAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestAbortRef = useRef<AbortController | null>(null);
  const requestSeqRef = useRef(0);

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
    requestAbortRef.current?.abort();
    const abortController = new AbortController();
    requestAbortRef.current = abortController;
    const requestSeq = ++requestSeqRef.current;
    const isLatest = () => requestSeq === requestSeqRef.current;
    void bridge
      .getIndustrialAnalysis(abortController.signal)
      .then((payload) => {
        if (!isLatest()) return;
        if (cacheKey) {
          industrialAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        if (!isLatest() || abortController.signal.aborted) return;
        setError(err instanceof Error ? err.message : "工控分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        if (requestAbortRef.current === abortController) {
          requestAbortRef.current = null;
        }
        if (isLatest()) {
          setLoading(false);
        }
      });
    return () => {
      abortController.abort();
      if (requestAbortRef.current === abortController) {
        requestAbortRef.current = null;
      }
    };
  }, [backendConnected, cacheKey, captureRevision]);

  useEffect(() => () => {
    requestAbortRef.current?.abort();
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(96,165,250,0.26),transparent_36%),linear-gradient(180deg,#f7fbff_0%,#f6f7ff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Factory className="h-5 w-5" />}
        title="工控分析"
        subtitle="INDUSTRIAL PROTOCOLS"
        description="聚焦 Modbus 与其他工控协议的会话、功能码、异常响应和控制指令，用统一视图快速识别危险写操作。"
        tags={INDUSTRIAL_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="blue"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <div className="mb-3 rounded-2xl border border-blue-100 bg-white/88 px-4 py-3 text-xs font-medium text-slate-500 shadow-[0_18px_48px_rgba(148,163,184,0.14)] backdrop-blur-xl">正在调用 tshark 生成工控分析结果...</div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded-2xl border border-amber-200 bg-amber-50/88 px-4 py-3 text-xs text-amber-700 shadow-[0_18px_48px_rgba(245,158,11,0.12)] backdrop-blur-xl">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="工控相关包" value={analysis.totalIndustrialPackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="Modbus 帧" value={analysis.modbus.totalFrames.toLocaleString()} />
        <StatCard title="异常响应" value={analysis.modbus.exceptions.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="工控协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" />
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
          <BucketChart data={analysis.modbus.functionCodes} barClassName="bg-indigo-500" />
        </Panel>
        <Panel title="Modbus Unit ID">
          <BucketChart data={analysis.modbus.unitIds} barClassName="bg-cyan-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="寄存器 / 线圈引用">
          <BucketChart data={analysis.modbus.referenceHits} barClassName="bg-emerald-500" />
        </Panel>
        <Panel title="异常码">
          <BucketChart data={analysis.modbus.exceptionCodes} barClassName="bg-rose-500" />
        </Panel>
      </div>

      {(analysis.ruleHits?.length ?? 0) > 0 && (
        <Panel title={`规则检测 / Modbus 异常命中 (${analysis.ruleHits!.length})`} className="mt-4">
          <AnalysisCallout className="mb-2" tone="blue" icon={<Shield className="h-4 w-4" />}>
            基于主从角色、功能码、数量字段、位长度一致性和高频写入行为生成规则命中，可直接定位可疑包与目标地址。
          </AnalysisCallout>
          <div className="max-h-[460px] overflow-auto">
            <table className="w-full table-fixed border-collapse text-left text-xs">
              <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
                <tr>
                  <th className="w-20 px-3 py-2">等级</th>
                  <th className="w-28 px-3 py-2">规则</th>
                  <th className="w-20 px-3 py-2">包号</th>
                  <th className="w-28 px-3 py-2">时间</th>
                  <th className="w-32 px-3 py-2">源</th>
                  <th className="w-32 px-3 py-2">目标</th>
                  <th className="w-24 px-3 py-2">功能码</th>
                  <th className="w-32 px-3 py-2">对象</th>
                  <th className="w-40 px-3 py-2">证据</th>
                  <th className="px-3 py-2">摘要</th>
                </tr>
              </thead>
              <tbody>
                {analysis.ruleHits!.map((item, idx) => (
                  <tr key={`${item.rule}-${item.packetId}-${idx}`} className="border-b border-border/70 align-top">
                    <td className="px-3 py-2">
                      <AnalysisBadge tone={toneForIndustrialRuleLevel(item.level)}>{item.level || "info"}</AnalysisBadge>
                    </td>
                    <td className="px-3 py-2 font-medium">{item.rule}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{item.packetId || "--"}</td>
                    <td className="px-3 py-2 font-mono">{item.time || "--"}</td>
                    <td className="px-3 py-2 break-all">{item.source || "--"}</td>
                    <td className="px-3 py-2 break-all">{item.destination || "--"}</td>
                    <td className="px-3 py-2">
                      {item.functionCode ? (
                        <div>
                          <div className="font-mono">{String(item.functionCode).padStart(2, "0")}</div>
                          {item.functionName && <div className="text-muted-foreground">{item.functionName}</div>}
                        </div>
                      ) : "--"}
                    </td>
                    <td className="px-3 py-2 font-mono break-all">{item.target || "--"}</td>
                    <td className="px-3 py-2 break-all font-mono text-[11px] text-muted-foreground">{item.evidence || "--"}</td>
                    <td className="px-3 py-2">{item.summary || "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel title="分析提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.notes.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到工控协议。</div>
          ) : (
            analysis.notes.map((note, index) => (
              <AnalysisCallout key={`${note}-${index}`} tone="blue" icon={<Workflow className="h-4 w-4" />}>
                {note}
              </AnalysisCallout>
            ))
          )}
        </div>
      </Panel>

      {(analysis.suspiciousWrites?.length ?? 0) > 0 && (
        <Panel title={`Modbus 可疑写操作 (${analysis.suspiciousWrites!.length})`} className="mt-4">
          <AnalysisCallout className="mb-2" tone="amber" icon={<AlertTriangle className="h-4 w-4" />}>
            以下为按写入次数排序的 Modbus 写操作聚合，高频写入可能对应灯控、阀门切换或寄存器篡改。
          </AnalysisCallout>
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
          <AnalysisCallout className="mb-2" tone="rose" icon={<Shield className="h-4 w-4" />}>
            以下为从 IEC 104、DNP3、BACnet 等协议中提取的控制/操作类指令，可能涉及遥控、设点或设备重启。
          </AnalysisCallout>
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
                      <AnalysisBadge tone="blue">{cmd.protocol}</AnalysisBadge>
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
                      <AnalysisBadge tone={toneForIndustrialTransactionKind(item.kind)}>{item.kind}</AnalysisBadge>
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
              <BucketChart data={detail.operations} barClassName="bg-blue-500" />
            </Panel>
            <Panel title="目标对象">
              <BucketChart data={detail.targets} barClassName="bg-emerald-500" />
            </Panel>
            <Panel title="结果 / 状态">
              <BucketChart data={detail.results} barClassName="bg-amber-500" />
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
    </PageShell>
  );
}

function toneForIndustrialRuleLevel(level: string): AnalysisTone {
  switch (String(level ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "rose";
    case "warning":
      return "amber";
    default:
      return "blue";
  }
}

function toneForIndustrialTransactionKind(kind: string): AnalysisTone {
  switch (kind) {
    case "request":
      return "blue";
    case "response":
      return "emerald";
    default:
      return "rose";
  }
}

export function buildIndustrialAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
