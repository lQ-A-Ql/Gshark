import { Car, FolderOpen, Route, ShieldAlert, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import type { DBCProfile, TrafficBucket, VehicleAnalysis as VehicleAnalysisData } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

const EMPTY_ANALYSIS: VehicleAnalysisData = {
  totalVehiclePackets: 0,
  protocols: [],
  conversations: [],
  can: {
    totalFrames: 0,
    extendedFrames: 0,
    rtrFrames: 0,
    errorFrames: 0,
    busIds: [],
    messageIds: [],
    payloadProtocols: [],
    payloadRecords: [],
    dbcProfiles: [],
    decodedMessageDist: [],
    decodedSignals: [],
    decodedMessages: [],
    signalTimelines: [],
    frames: [],
  },
  j1939: {
    totalMessages: 0,
    pgns: [],
    sourceAddrs: [],
    targetAddrs: [],
    messages: [],
  },
  doip: {
    totalMessages: 0,
    messageTypes: [],
    vins: [],
    endpoints: [],
    messages: [],
  },
  uds: {
    totalMessages: 0,
    serviceIDs: [],
    negativeCodes: [],
    dtcs: [],
    vins: [],
    messages: [],
    transactions: [],
  },
  recommendations: [],
};

const vehicleAnalysisCache = new Map<string, VehicleAnalysisData>();
const MAX_CAN_DATA_LINES_PER_ID = 12;
const VEHICLE_PROTOCOL_TAGS = ["CAN", "J1939", "DoIP", "UDS"];

interface CanIdDataLine {
  packetId: number;
  label: string;
  value: string;
  meta: string;
}

interface CanIdDataGroup {
  identifier: string;
  busId: string;
  total: number;
  observedCount: number;
  hiddenCount: number;
  items: CanIdDataLine[];
}

export default function VehicleAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets } = useSentinel();
  const [dbcProfiles, setDBCProfiles] = useState<DBCProfile[]>([]);
  const [dbcPathInput, setDBCPathInput] = useState("");
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    const dbcKey = dbcProfiles.map((item) => item.path).sort().join("|");
    return `${fileMeta.path}::${totalPackets}::${dbcKey}`;
  }, [dbcProfiles, fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<VehicleAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const canIdDataGroups = useMemo(() => buildCanIdDataGroups(analysis), [analysis]);

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_ANALYSIS);
      return;
    }
    if (!force && cacheKey && vehicleAnalysisCache.has(cacheKey)) {
      setAnalysis(vehicleAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    void bridge
      .getVehicleAnalysis()
      .then((payload) => {
        if (cacheKey) {
          vehicleAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "车机流量分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [backendConnected, cacheKey]);

  const refreshDBCProfiles = useCallback(() => {
    if (!backendConnected) {
      setDBCProfiles([]);
      return;
    }
    void bridge
      .listVehicleDBCProfiles()
      .then((items) => setDBCProfiles(items))
      .catch(() => setDBCProfiles([]));
  }, [backendConnected]);

  const addDBC = useCallback(async (path: string) => {
    const normalized = path.trim();
    if (!normalized) return;
    try {
      const profiles = await bridge.addVehicleDBC(normalized);
      vehicleAnalysisCache.clear();
      setDBCProfiles(profiles);
      setDBCPathInput("");
      setError("");
      refreshAnalysis(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "DBC 导入失败");
    }
  }, [refreshAnalysis]);

  const removeDBC = useCallback(async (path: string) => {
    try {
      const profiles = await bridge.removeVehicleDBC(path);
      vehicleAnalysisCache.clear();
      setDBCProfiles(profiles);
      setError("");
      refreshAnalysis(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "DBC 移除失败");
    }
  }, [refreshAnalysis]);

  const importDBC = useCallback(() => {
    void bridge
      .openDBCFile()
      .then((file) => addDBC(file.filePath))
      .catch((err) => {
        if (err instanceof Error && err.message !== "未选择 DBC 文件") {
          setError(err.message);
        }
      });
  }, [addDBC]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshDBCProfiles();
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis, refreshDBCProfiles]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <AnalysisHero
        icon={<Car className="h-5 w-5" />}
        title="车机流量分析"
        subtitle="AUTOMOTIVE PROTOCOLS"
        tags={VEHICLE_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="emerald"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在调用 tshark 生成车机分析结果...</div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <Panel title="DBC 映射" className="mb-4">
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-3 py-2 text-xs hover:bg-accent"
              onClick={importDBC}
            >
              <FolderOpen className="h-4 w-4" />
              导入 DBC
            </button>
            <input
              value={dbcPathInput}
              onChange={(event) => setDBCPathInput(event.target.value)}
              placeholder="或直接输入 DBC 文件路径"
              className="min-w-[320px] flex-1 rounded border border-border bg-background px-3 py-2 text-xs outline-none focus:border-blue-400"
            />
            <button
              className="rounded border border-border bg-background px-3 py-2 text-xs hover:bg-accent"
              onClick={() => void addDBC(dbcPathInput)}
            >
              添加路径
            </button>
          </div>
          {dbcProfiles.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-xs text-muted-foreground">
              当前未加载 DBC。导入后，CAN 报文会尝试直接映射为报文名和信号值。
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
              {dbcProfiles.map((profile) => (
                <div key={profile.path} className="flex items-start justify-between rounded border border-border bg-background px-3 py-3 text-xs">
                  <div className="min-w-0">
                    <div className="font-medium text-foreground">{profile.name}</div>
                    <div className="truncate text-muted-foreground" title={profile.path}>{profile.path}</div>
                    <div className="mt-1 text-muted-foreground">报文 {profile.messageCount} / 信号 {profile.signalCount}</div>
                  </div>
                  <button
                    className="ml-3 rounded border border-border p-2 text-muted-foreground hover:bg-accent hover:text-foreground"
                    onClick={() => void removeDBC(profile.path)}
                    title="移除 DBC"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="车载相关包" value={analysis.totalVehiclePackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="CAN 帧" value={analysis.can.totalFrames.toLocaleString()} />
        <StatCard title="DBC 解码报文" value={analysis.can.decodedMessages.length.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="车载协议分布">
          <BucketChart data={analysis.protocols} color="bg-blue-500" />
        </Panel>
        <Panel title="网络 / 总线视图">
          <ConversationList
            items={analysis.conversations.map((item) => ({
              label: item.protocol ? `${item.protocol} · ${item.label}` : item.label,
              count: item.count,
            }))}
          />
        </Panel>
      </div>

      <Panel title="分析方案" className="mt-4">
        <div className="space-y-2 text-sm">
          <div className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
            <Route className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            <span>第一层先做总线基线：看 CAN ID、总线错误帧、J1939 PGN 分布，识别异常节点和异常广播。</span>
          </div>
          <div className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
            <Route className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            <span>第二层做诊断链路：围绕 DoIP 寻址、UDS 会话切换、安全访问、刷写和例程调用，确认是否存在高风险诊断行为。</span>
          </div>
          <div className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
            <Route className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            <span>第三层做安全专项：重点审计 SID 0x27、0x31、0x34、0x36、0x37 和负响应码，判断鉴权绕过、固件下发和诊断滥用。</span>
          </div>
        </div>
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="CAN 总线">
          <div className="mb-4 grid grid-cols-2 gap-3">
            <MiniStat title="扩展帧" value={analysis.can.extendedFrames} />
            <MiniStat title="错误帧" value={analysis.can.errorFrames} />
            <MiniStat title="RTR 帧" value={analysis.can.rtrFrames} />
            <MiniStat title="DBC 信号" value={analysis.can.decodedSignals.length} />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <BucketChart data={analysis.can.busIds} color="bg-cyan-500" />
            <BucketChart data={analysis.can.messageIds} color="bg-indigo-500" />
          </div>
        </Panel>
        <Panel title="J1939">
          <div className="mb-4 grid grid-cols-2 gap-3">
            <MiniStat title="消息数" value={analysis.j1939.totalMessages} />
            <MiniStat title="PGN 种类" value={analysis.j1939.pgns.length} />
            <MiniStat title="源地址种类" value={analysis.j1939.sourceAddrs.length} />
            <MiniStat title="目标地址种类" value={analysis.j1939.targetAddrs.length} />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <BucketChart data={analysis.j1939.pgns} color="bg-emerald-500" />
            <BucketChart data={analysis.j1939.sourceAddrs} color="bg-violet-500" />
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="DoIP">
          <div className="mb-4 grid grid-cols-2 gap-3">
            <MiniStat title="消息数" value={analysis.doip.totalMessages} />
            <MiniStat title="VIN" value={analysis.doip.vins.length} />
            <MiniStat title="消息类型" value={analysis.doip.messageTypes.length} />
            <MiniStat title="逻辑地址" value={analysis.doip.endpoints.length} />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <BucketChart data={analysis.doip.messageTypes} color="bg-sky-500" />
            <BucketChart data={analysis.doip.vins} color="bg-fuchsia-500" />
          </div>
        </Panel>
        <Panel title="UDS">
          <div className="mb-4 grid grid-cols-2 gap-3">
            <MiniStat title="消息数" value={analysis.uds.totalMessages} />
            <MiniStat title="服务数" value={analysis.uds.serviceIDs.length} />
            <MiniStat title="负响应码" value={analysis.uds.negativeCodes.length} />
            <MiniStat title="DTC 数" value={analysis.uds.dtcs.length} />
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <BucketChart data={analysis.uds.serviceIDs} color="bg-orange-500" />
            <BucketChart data={analysis.uds.negativeCodes} color="bg-rose-500" />
          </div>
        </Panel>
      </div>

      <Panel title="安全提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.recommendations.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到车载协议。</div>
          ) : (
            analysis.recommendations.map((note, index) => (
              <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                <span>{note}</span>
              </div>
            ))
          )}
        </div>
      </Panel>

      <Panel title={`CAN 明细预览 (${analysis.can.frames.length} / ${analysis.can.totalFrames})`} className="mt-4">
        <DataTable
          headers={["包号", "时间", "Bus", "ID", "长度", "标志", "摘要"]}
          rows={analysis.can.frames.map((item) => [
            item.packetId,
            item.time || "--",
            item.busId || "--",
            item.identifier || "--",
            item.length || 0,
            [item.isExtended ? "XTD" : "", item.isRTR ? "RTR" : "", item.isError ? item.errorFlags || "ERR" : ""].filter(Boolean).join(" / ") || "--",
            item.summary || "--",
          ])}
        />
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="CAN Payload 协议分布">
          <BucketChart data={analysis.can.payloadProtocols} color="bg-amber-500" />
        </Panel>
        <Panel title={`CAN Payload 明细预览 (${analysis.can.payloadRecords.length})`}>
          <DataTable
            headers={["包号", "时间", "Bus", "ID", "协议", "帧类型", "地址", "服务", "细节", "长度", "摘要"]}
            rows={analysis.can.payloadRecords.map((item) => [
              item.packetId,
              item.time || "--",
              item.busId || "--",
              item.identifier || "--",
              item.protocol || "--",
              item.frameType || "--",
              [item.sourceAddress, item.targetAddress].filter(Boolean).join(" -> ") || "--",
              item.service || "--",
              item.detail || item.rawData || "--",
              item.length || 0,
              item.summary || "--",
            ])}
          />
        </Panel>
      </div>

      <Panel title={`CAN ID 数据区域 (${canIdDataGroups.length})`} className="mt-4">
        <CanIdDataBoard groups={canIdDataGroups} />
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="DBC 报文分布">
          <BucketChart data={analysis.can.decodedMessageDist} color="bg-emerald-500" />
        </Panel>
        <Panel title="DBC 信号分布">
          <BucketChart data={analysis.can.decodedSignals} color="bg-violet-500" />
        </Panel>
      </div>

      <Panel title={`DBC 解码明细预览 (${analysis.can.decodedMessages.length})`} className="mt-4">
        <DataTable
          headers={["包号", "时间", "Bus", "ID", "数据库", "报文", "发送方", "信号", "摘要"]}
          rows={analysis.can.decodedMessages.map((item) => [
            item.packetId,
            item.time || "--",
            item.busId || "--",
            item.identifier || "--",
            item.database || "--",
            item.messageName || "--",
            item.sender || "--",
            item.signals.map((signal) => `${signal.name}=${signal.value}${signal.unit ? ` ${signal.unit}` : ""}`).join(" ; ") || "--",
            item.summary || "--",
          ])}
        />
      </Panel>

      <Panel title={`DBC 信号时间线 (${analysis.can.signalTimelines.length})`} className="mt-4">
        <DataTable
          headers={["信号", "样本数", "最新值", "最小值", "最大值", "单位", "最近报文"]}
          rows={analysis.can.signalTimelines.map((timeline) => {
            const values = timeline.samples.map((sample) => sample.value);
            const latest = timeline.samples[timeline.samples.length - 1];
            const min = Math.min(...values);
            const max = Math.max(...values);
            return [
              timeline.name,
              timeline.samples.length,
              latest ? latest.value : "--",
              Number.isFinite(min) ? min : "--",
              Number.isFinite(max) ? max : "--",
              latest?.unit || "--",
              latest?.messageName || "--",
            ];
          })}
        />
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title={`DoIP 明细预览 (${analysis.doip.messages.length} / ${analysis.doip.totalMessages})`}>
          <DataTable
            headers={["包号", "时间", "源", "目标", "类型", "VIN", "状态", "摘要"]}
            rows={analysis.doip.messages.map((item) => [
              item.packetId,
              item.time || "--",
              item.source || "--",
              item.destination || "--",
              item.type || "--",
              item.vin || "--",
              item.responseCode || item.diagnosticState || "--",
              item.summary || "--",
            ])}
          />
        </Panel>
        <Panel title={`UDS 明细预览 (${analysis.uds.messages.length} / ${analysis.uds.totalMessages})`}>
          <DataTable
            headers={["包号", "时间", "SID", "名称", "源", "目标", "DID/DTC", "摘要"]}
            rows={analysis.uds.messages.map((item) => [
              item.packetId,
              item.time || "--",
              item.serviceId || "--",
              item.serviceName || "--",
              item.sourceAddress || "--",
              item.targetAddress || "--",
              item.dataIdentifier || item.dtc || item.negativeCode || "--",
              item.summary || "--",
            ])}
          />
        </Panel>
      </div>

      <Panel title={`UDS 配对事务预览 (${analysis.uds.transactions.length})`} className="mt-4">
        <DataTable
          headers={["请求包", "响应包", "时间", "地址", "服务", "对象", "状态", "耗时(ms)", "摘要"]}
          rows={analysis.uds.transactions.map((item) => [
            item.requestPacketId || "--",
            item.responsePacketId || "--",
            [item.requestTime, item.responseTime].filter(Boolean).join(" -> ") || "--",
            [item.sourceAddress, item.targetAddress].filter(Boolean).join(" -> ") || "--",
            [item.serviceId, item.serviceName].filter(Boolean).join(" ") || "--",
            item.dataIdentifier || item.dtc || item.subFunction || "--",
            item.negativeCode ? `${item.status} / ${item.negativeCode}` : item.status || "--",
            item.latencyMs ?? "--",
            item.responseSummary || item.requestSummary || "--",
          ])}
        />
      </Panel>
    </div>
  );
}

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-2 text-xs text-muted-foreground">{title}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

function MiniStat({ title, value }: { title: string; value: number }) {
  return (
    <div className="rounded border border-border bg-background px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{title}</div>
      <div className="text-sm font-semibold">{value.toLocaleString()}</div>
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
    <div className="max-h-[320px] overflow-auto pr-1">
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
    <div className="max-h-[320px] space-y-2 overflow-auto pr-1">
      {items.map((item) => (
        <div key={`${item.label}-${item.count}`} className="flex items-center justify-between rounded border border-border bg-background px-3 py-2 text-xs">
          <span className="truncate text-muted-foreground" title={item.label}>{item.label}</span>
          <span className="ml-3 font-mono">{item.count}</span>
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

function CanIdDataBoard({ groups }: { groups: CanIdDataGroup[] }) {
  if (groups.length === 0) {
    return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">暂无可展示的 CAN ID 数据</div>;
  }

  return (
    <div className="max-h-[520px] overflow-auto pr-1">
      <div className="space-y-3">
        {groups.map((group) => (
          <div key={`${group.identifier}-${group.busId}`} className="overflow-hidden rounded-lg border border-border bg-background">
            <div className="grid grid-cols-[156px_1fr]">
              <div className="border-r border-border bg-accent/20 px-3 py-3">
                <div className="text-[11px] text-muted-foreground">CAN ID</div>
                <div className="mt-1 font-mono text-sm font-semibold text-foreground">{group.identifier}</div>
                <div className="mt-2 text-[11px] text-muted-foreground">Bus {group.busId || "--"}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">唯一 DATA {group.total} 条</div>
                <div className="mt-1 text-[11px] text-muted-foreground">原始帧 {group.observedCount} 条</div>
              </div>
              <div className="divide-y divide-border/70">
                {group.items.map((item) => (
                  <div key={`${group.identifier}-${item.packetId}-${item.label}`} className="px-3 py-2">
                    <div className="text-[11px] text-muted-foreground">{item.label} · {item.meta}</div>
                    <div className="mt-1 break-all font-mono text-xs text-foreground">{item.value}</div>
                  </div>
                ))}
                {group.hiddenCount > 0 && (
                  <div className="px-3 py-2 text-[11px] text-muted-foreground">
                    还有 {group.hiddenCount} 条数据未展开，保留在原始 CAN Payload / DBC 区域中查看。
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function buildCanIdDataGroups(analysis: VehicleAnalysisData): CanIdDataGroup[] {
  const grouped = new Map<string, {
    identifier: string;
    busId: string;
    observedCount: number;
    items: CanIdDataLine[];
    seenValues: Set<string>;
  }>();
  const orderedKeys: string[] = [];

  for (const frame of analysis.can.frames) {
    const identifier = frame.identifier?.trim() || "--";
    const busId = frame.busId?.trim() || "--";
    const rawData = frame.rawData?.trim() || "";
    if (!rawData) {
      continue;
    }
    const key = `${identifier}@@${busId}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        identifier,
        busId,
        observedCount: 0,
        items: [],
        seenValues: new Set<string>(),
      });
      orderedKeys.push(key);
    }

    const group = grouped.get(key)!;
    group.observedCount += 1;
    if (group.seenValues.has(rawData)) {
      continue;
    }
    group.seenValues.add(rawData);

    const meta = [
      frame.time?.trim(),
      frame.length > 0 ? `len=${frame.length}` : "",
      frame.packetId ? `#${frame.packetId}` : "",
    ].filter(Boolean).join(" · ");

    group.items.push({
      packetId: frame.packetId,
      label: `DATA${group.items.length + 1}`,
      value: rawData,
      meta: meta || "--",
    });
  }

  return orderedKeys.map((key) => {
    const group = grouped.get(key)!;
    const total = group.items.length;
    return {
      identifier: group.identifier,
      busId: group.busId,
      total,
      observedCount: group.observedCount,
      hiddenCount: Math.max(0, total - MAX_CAN_DATA_LINES_PER_ID),
      items: group.items.slice(0, MAX_CAN_DATA_LINES_PER_ID),
    };
  });
}
