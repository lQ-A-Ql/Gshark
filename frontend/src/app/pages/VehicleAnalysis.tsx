import { Car, Route, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisDataTable as DataTable,
  AnalysisList as ConversationList,
  AnalysisMiniStat as MiniStat,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../components/analysis/AnalysisPrimitives";
import type { DBCProfile } from "../core/types";
import { CanIdDataBoard, buildCanIdDataGroups } from "../features/vehicle/VehicleCanDataBoard";
import { VehicleDbcPanel } from "../features/vehicle/VehicleDbcPanel";
import { VehicleUdsTransactionsPanel } from "../features/vehicle/VehicleUdsTransactionsPanel";
import { useVehicleAnalysis } from "../features/vehicle/useVehicleAnalysis";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";
const VEHICLE_PROTOCOL_TAGS = ["CAN", "J1939", "DoIP", "UDS"];

export default function VehicleAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [dbcProfiles, setDBCProfiles] = useState<DBCProfile[]>([]);
  const [dbcPathInput, setDBCPathInput] = useState("");
  const {
    analysis,
    loading,
    error: analysisError,
    refreshAnalysis,
  } = useVehicleAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    dbcProfiles,
  });
  const [pageError, setPageError] = useState("");
  const error = analysisError || pageError;
  const canIdDataGroups = useMemo(() => buildCanIdDataGroups(analysis), [analysis]);
  const [udsStatusFilter, setUdsStatusFilter] = useState("all");
  const filteredUdsTransactions = useMemo(() => {
    if (udsStatusFilter === "all") return analysis.uds.transactions;
    return analysis.uds.transactions.filter((t) => t.status === udsStatusFilter);
  }, [analysis.uds.transactions, udsStatusFilter]);

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

  const addDBC = useCallback(
    async (path: string) => {
      const normalized = path.trim();
      if (!normalized) return;
      try {
        const profiles = await bridge.addVehicleDBC(normalized);
        setDBCProfiles(profiles);
        setDBCPathInput("");
        setPageError("");
        refreshAnalysis(true);
      } catch (err) {
        setPageError(err instanceof Error ? err.message : "DBC 导入失败");
      }
    },
    [refreshAnalysis],
  );

  const removeDBC = useCallback(
    async (path: string) => {
      try {
        const profiles = await bridge.removeVehicleDBC(path);
        setDBCProfiles(profiles);
        setPageError("");
        refreshAnalysis(true);
      } catch (err) {
        setPageError(err instanceof Error ? err.message : "DBC 移除失败");
      }
    },
    [refreshAnalysis],
  );

  const importDBC = useCallback(() => {
    void bridge
      .openDBCFile()
      .then((file) => addDBC(file.filePath))
      .catch((err) => {
        if (err instanceof Error && err.message !== "未选择 DBC 文件") {
          setPageError(err.message);
        }
      });
  }, [addDBC]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshDBCProfiles();
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis, refreshDBCProfiles]);

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(52,211,153,0.24),transparent_36%),linear-gradient(180deg,#f4fffb_0%,#f6f7ff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Car className="h-5 w-5" />}
        title="车机流量分析"
        subtitle="AUTOMOTIVE PROTOCOLS"
        description="统一查看 CAN、J1939、DoIP、UDS 等车载协议，并在同一页处理 DBC 映射、诊断事务和安全提示。"
        tags={VEHICLE_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="emerald"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <StatusHint tone="slate" className="mb-3">
          正在调用 tshark 生成车机分析结果...
        </StatusHint>
      )}

      {!loading && error && (
        <StatusHint tone="amber" className="mb-3">
          {error}
        </StatusHint>
      )}

      <VehicleDbcPanel
        profiles={dbcProfiles}
        pathInput={dbcPathInput}
        onPathInputChange={setDBCPathInput}
        onImport={importDBC}
        onAddPath={() => void addDBC(dbcPathInput)}
        onRemove={(path) => void removeDBC(path)}
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="车载相关包" value={analysis.totalVehiclePackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="CAN 帧" value={analysis.can.totalFrames.toLocaleString()} />
        <StatCard title="DBC 解码报文" value={analysis.can.decodedMessages.length.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="车载协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" maxHeightClassName="max-h-[320px]" />
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
            <span>
              第二层做诊断链路：围绕 DoIP 寻址、UDS 会话切换、安全访问、刷写和例程调用，确认是否存在高风险诊断行为。
            </span>
          </div>
          <div className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
            <Route className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
            <span>
              第三层做安全专项：重点审计 SID 0x27、0x31、0x34、0x36、0x37 和负响应码，判断鉴权绕过、固件下发和诊断滥用。
            </span>
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
            <BucketChart data={analysis.can.busIds} barClassName="bg-cyan-500" maxHeightClassName="max-h-[320px]" />
            <BucketChart
              data={analysis.can.messageIds}
              barClassName="bg-indigo-500"
              maxHeightClassName="max-h-[320px]"
            />
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
            <BucketChart data={analysis.j1939.pgns} barClassName="bg-emerald-500" maxHeightClassName="max-h-[320px]" />
            <BucketChart
              data={analysis.j1939.sourceAddrs}
              barClassName="bg-violet-500"
              maxHeightClassName="max-h-[320px]"
            />
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
            <BucketChart
              data={analysis.doip.messageTypes}
              barClassName="bg-sky-500"
              maxHeightClassName="max-h-[320px]"
            />
            <BucketChart data={analysis.doip.vins} barClassName="bg-fuchsia-500" maxHeightClassName="max-h-[320px]" />
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
            <BucketChart
              data={analysis.uds.serviceIDs}
              barClassName="bg-orange-500"
              maxHeightClassName="max-h-[320px]"
            />
            <BucketChart
              data={analysis.uds.negativeCodes}
              barClassName="bg-rose-500"
              maxHeightClassName="max-h-[320px]"
            />
          </div>
        </Panel>
      </div>

      <Panel title="安全提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.recommendations.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">
              当前抓包未识别到车载协议。
            </div>
          ) : (
            analysis.recommendations.map((note, index) => (
              <div
                key={`${note}-${index}`}
                className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2"
              >
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
            [item.isExtended ? "XTD" : "", item.isRTR ? "RTR" : "", item.isError ? item.errorFlags || "ERR" : ""]
              .filter(Boolean)
              .join(" / ") || "--",
            item.summary || "--",
          ])}
        />
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="CAN Payload 协议分布">
          <BucketChart
            data={analysis.can.payloadProtocols}
            barClassName="bg-amber-500"
            maxHeightClassName="max-h-[320px]"
          />
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
          <BucketChart
            data={analysis.can.decodedMessageDist}
            barClassName="bg-emerald-500"
            maxHeightClassName="max-h-[320px]"
          />
        </Panel>
        <Panel title="DBC 信号分布">
          <BucketChart
            data={analysis.can.decodedSignals}
            barClassName="bg-violet-500"
            maxHeightClassName="max-h-[320px]"
          />
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
            item.signals
              .map((signal) => `${signal.name}=${signal.value}${signal.unit ? ` ${signal.unit}` : ""}`)
              .join(" ; ") || "--",
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

      <VehicleUdsTransactionsPanel
        transactions={analysis.uds.transactions}
        filteredTransactions={filteredUdsTransactions}
        statusFilter={udsStatusFilter}
        onStatusFilterChange={setUdsStatusFilter}
      />
    </PageShell>
  );
}
