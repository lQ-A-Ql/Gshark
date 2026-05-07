import { AlertTriangle, Factory, Shield, Workflow } from "lucide-react";
import { useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
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
import { useSentinel } from "../state/SentinelContext";
import { useIndustrialAnalysis } from "../features/industrial/useIndustrialAnalysis";
import { EvidenceActions } from "../misc/EvidenceActions";
import { cn } from "../components/ui/utils";

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
  const { analysis, loading, error, refreshAnalysis } = useIndustrialAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const [modbusUnitFilter, setModbusUnitFilter] = useState("all");
  const [modbusFunctionFilter, setModbusFunctionFilter] = useState("all");

  const modbusUnitOptions = useMemo(() => {
    const units = new Set(analysis.modbus.transactions.map((t) => String(t.unitId)));
    return ["all", ...Array.from(units).sort()];
  }, [analysis.modbus.transactions]);

  const modbusFunctionOptions = useMemo(() => {
    const fns = new Set(analysis.modbus.transactions.map((t) => String(t.functionCode)));
    return ["all", ...Array.from(fns).sort()];
  }, [analysis.modbus.transactions]);

  const filteredModbusTransactions = useMemo(() => {
    return analysis.modbus.transactions.filter((t) => {
      if (modbusUnitFilter !== "all" && String(t.unitId) !== modbusUnitFilter) return false;
      if (modbusFunctionFilter !== "all" && String(t.functionCode) !== modbusFunctionFilter) return false;
      return true;
    });
  }, [analysis.modbus.transactions, modbusUnitFilter, modbusFunctionFilter]);

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

      {loading && <StatusHint tone="slate" className="mb-3">正在调用 tshark 生成工控分析结果...</StatusHint>}

      {!loading && error && <StatusHint tone="amber" className="mb-3">{error}</StatusHint>}

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
          <DataTable
            columns={[
              {
                key: "level",
                header: "等级",
                widthClassName: "w-20",
                render: (item) => <AnalysisBadge tone={toneForIndustrialRuleLevel(item.level)}>{item.level || "info"}</AnalysisBadge>,
              },
              { key: "rule", header: "规则", widthClassName: "w-28", cellClassName: "font-medium", render: (item) => item.rule },
              { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (item) => item.packetId || "--" },
              { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (item) => item.time || "--" },
              { key: "source", header: "源", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.source || "--" },
              { key: "destination", header: "目标", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.destination || "--" },
              {
                key: "function",
                header: "功能码",
                widthClassName: "w-24",
                render: (item) => item.functionCode != null ? (
                  <div>
                    <div className="font-mono">{String(item.functionCode).padStart(2, "0")}</div>
                    {item.functionName && <div className="text-slate-500">{item.functionName}</div>}
                  </div>
                ) : "--",
              },
              { key: "target", header: "对象", widthClassName: "w-32", cellClassName: "break-all font-mono", render: (item) => item.target || "--" },
              { key: "evidence", header: "证据", widthClassName: "w-40", cellClassName: "break-all font-mono text-[11px] text-slate-500", render: (item) => item.evidence || "--" },
              { key: "summary", header: "摘要", render: (item) => item.summary || "--" },
            ]}
            data={analysis.ruleHits ?? []}
            rowKey={(item, idx) => `${item.rule}-${item.packetId}-${idx}`}
            maxHeightClassName="max-h-[460px]"
            tableClassName="min-w-[1120px]"
            emptyText="暂无规则命中"
          />
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
          <DataTable
            columns={[
              { key: "target", header: "目标地址", widthClassName: "w-36", cellClassName: "font-mono", render: (sw) => sw.target },
              { key: "unit", header: "Unit ID", widthClassName: "w-20", cellClassName: "font-mono", render: (sw) => sw.unitId || "--" },
              {
                key: "function",
                header: "功能码",
                widthClassName: "w-28",
                render: (sw) => (
                  <div>
                    <div className="font-mono">{String(sw.functionCode).padStart(2, "0")}</div>
                    <div className="text-slate-500">{sw.functionName}</div>
                  </div>
                ),
              },
              { key: "count", header: "写入次数", widthClassName: "w-20", cellClassName: "font-mono font-semibold text-amber-700", render: (sw) => sw.writeCount },
              { key: "sources", header: "来源 IP", widthClassName: "w-36", cellClassName: "font-mono", render: (sw) => sw.sources.join(", ") || "--" },
              { key: "first", header: "首次时间", widthClassName: "w-28", cellClassName: "font-mono", render: (sw) => sw.firstTime || "--" },
              { key: "last", header: "末次时间", widthClassName: "w-28", cellClassName: "font-mono", render: (sw) => sw.lastTime || "--" },
              {
                key: "samples",
                header: "样本值",
                render: (sw) => sw.sampleValues.length > 0 ? (
                  <div className="space-y-0.5">
                    {sw.sampleValues.map((value, valueIndex) => (
                      <div key={valueIndex} className="break-all font-mono text-[11px] text-slate-500">{value}</div>
                    ))}
                  </div>
                ) : "--",
              },
              {
                key: "actions",
                header: "定位",
                widthClassName: "w-16",
                render: (sw) => sw.samplePacketId ? <EvidenceActions packetId={sw.samplePacketId} /> : "--",
              },
            ]}
            data={analysis.suspiciousWrites ?? []}
            rowKey={(_sw, idx) => `sw-${idx}`}
            maxHeightClassName="max-h-[420px]"
            tableClassName="min-w-[920px]"
            emptyText="暂无可疑写操作"
          />
        </Panel>
      )}

      {(analysis.modbus.decodedInputs?.length ?? 0) > 0 && (
        <Panel title={`Modbus UTF-8 输入重组 (${analysis.modbus.decodedInputs!.length})`} className="mt-4">
          <AnalysisCallout className="mb-2" tone="blue" icon={<Workflow className="h-4 w-4" />}>
            将连续写寄存器中的 ASCII 数值按时间顺序重组；若重组结果本身是十六进制文本，则继续转为 UTF-8 显示。
          </AnalysisCallout>
          <DataTable
            columns={[
              {
                key: "range",
                header: "包范围",
                widthClassName: "w-28",
                cellClassName: "font-mono text-slate-500",
                render: (item) => `${item.startPacketId}-${item.endPacketId}`,
              },
              { key: "source", header: "源", widthClassName: "w-36", render: (item) => item.source || "--" },
              { key: "destination", header: "目标", widthClassName: "w-36", render: (item) => item.destination || "--" },
              {
                key: "function",
                header: "功能码",
                widthClassName: "w-28",
                render: (item) => (
                  <div>
                    <div className="font-mono">{item.functionCode || "--"}</div>
                    <div className="text-slate-500">{item.functionName || "--"}</div>
                  </div>
                ),
              },
              { key: "encoding", header: "编码", widthClassName: "w-32", cellClassName: "font-mono text-blue-700", render: (item) => item.encoding || "--" },
              {
                key: "text",
                header: "输入内容",
                render: (item) => (
                  <div className="max-h-32 overflow-y-auto rounded border border-emerald-100 bg-emerald-50/70 px-2 py-1 font-mono text-[11px] text-emerald-800">
                    <div className="whitespace-pre-wrap break-words">{item.text}</div>
                    {item.rawText && item.rawText !== item.text && (
                      <div className="mt-1 border-t border-emerald-100 pt-1 text-emerald-700/75">
                        原始 ASCII: <span className="whitespace-pre-wrap break-words">{item.rawText}</span>
                      </div>
                    )}
                  </div>
                ),
              },
              {
                key: "actions",
                header: "定位",
                widthClassName: "w-16",
                render: (item) => item.startPacketId ? <EvidenceActions packetId={item.startPacketId} /> : "--",
              },
            ]}
            data={analysis.modbus.decodedInputs ?? []}
            rowKey={(item, idx) => `decoded-input-${item.startPacketId}-${item.endPacketId}-${idx}`}
            maxHeightClassName="max-h-[420px]"
            tableClassName="min-w-[1120px]"
            emptyText="暂无可重组 UTF-8 输入"
          />
        </Panel>
      )}

      {(analysis.controlCommands?.length ?? 0) > 0 && (
        <Panel title={`控制指令 (${analysis.controlCommands!.length})`} className="mt-4">
          <AnalysisCallout className="mb-2" tone="rose" icon={<Shield className="h-4 w-4" />}>
            以下为从 IEC 104、DNP3、BACnet 等协议中提取的控制/操作类指令，可能涉及遥控、设点或设备重启。
          </AnalysisCallout>
          <DataTable
            columns={[
              { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (cmd) => cmd.packetId },
              { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (cmd) => cmd.time || "--" },
              { key: "protocol", header: "协议", widthClassName: "w-20", render: (cmd) => <AnalysisBadge tone="blue">{cmd.protocol}</AnalysisBadge> },
              { key: "source", header: "源", widthClassName: "w-32", render: (cmd) => cmd.source || "--" },
              { key: "destination", header: "目标", widthClassName: "w-32", render: (cmd) => cmd.destination || "--" },
              { key: "operation", header: "操作", widthClassName: "w-36", cellClassName: "font-mono font-semibold text-rose-700", render: (cmd) => cmd.operation || "--" },
              { key: "target", header: "对象", widthClassName: "w-28", cellClassName: "font-mono", render: (cmd) => cmd.target || "--" },
              { key: "value", header: "值", widthClassName: "w-24", cellClassName: "font-mono", render: (cmd) => cmd.value || "--" },
              { key: "result", header: "结果", widthClassName: "w-24", render: (cmd) => cmd.result || "--" },
              { key: "summary", header: "摘要", render: (cmd) => cmd.summary || "--" },
            ]}
            data={analysis.controlCommands ?? []}
            rowKey={(_cmd, idx) => `cmd-${idx}`}
            maxHeightClassName="max-h-[520px]"
            tableClassName="min-w-[1120px]"
            emptyText="暂无控制指令"
          />
        </Panel>
      )}

      <Panel title={`Modbus 事务明细 (${filteredModbusTransactions.length})`} className="mt-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-slate-500">Unit ID:</span>
          {modbusUnitOptions.map((u) => (
            <button
              key={u}
              type="button"
              onClick={() => setModbusUnitFilter(u)}
              className={cn(
                "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
                modbusUnitFilter === u
                  ? "border-blue-200 bg-blue-100 text-blue-700"
                  : "border-slate-200 bg-white/80 text-slate-500 hover:border-blue-200",
              )}
            >
              {u === "all" ? "全部" : u}
            </button>
          ))}
          <span className="ml-3 text-[11px] font-medium text-slate-500">功能码:</span>
          {modbusFunctionOptions.map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setModbusFunctionFilter(f)}
              className={cn(
                "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
                modbusFunctionFilter === f
                  ? "border-blue-200 bg-blue-100 text-blue-700"
                  : "border-slate-200 bg-white/80 text-slate-500 hover:border-blue-200",
              )}
            >
              {f === "all" ? "全部" : f}
            </button>
          ))}
        </div>
        <DataTable
          columns={[
            { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (item) => item.packetId },
            { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (item) => item.time || "--" },
            { key: "source", header: "源", widthClassName: "w-40", render: (item) => item.source || "--" },
            { key: "destination", header: "目标", widthClassName: "w-40", render: (item) => item.destination || "--" },
            {
              key: "function",
              header: "功能码",
              widthClassName: "w-28",
              render: (item) => (
                <div>
                  <div className="font-mono">{item.functionCode || "--"}</div>
                  <div className="text-slate-500">{item.functionName || "--"}</div>
                </div>
              ),
            },
            { key: "kind", header: "类型", widthClassName: "w-20", render: (item) => <AnalysisBadge tone={toneForIndustrialTransactionKind(item.kind)}>{item.kind}</AnalysisBadge> },
            { key: "unit", header: "Unit", widthClassName: "w-24", cellClassName: "font-mono", render: (item) => item.unitId || "--" },
            { key: "reference", header: "引用", widthClassName: "w-28", cellClassName: "font-mono", render: (item) => item.reference || "--" },
            { key: "quantity", header: "数量", widthClassName: "w-20", cellClassName: "font-mono", render: (item) => item.quantity || "--" },
            { key: "latency", header: "耗时", widthClassName: "w-20", cellClassName: "font-mono", render: (item) => item.responseTime || "--" },
            {
              key: "summary",
              header: "摘要",
              render: (item) => (
                <div>
                  <div>{item.summary || "--"}</div>
                  {item.bitRange?.preview && (
                    <div className="mt-1 break-all font-mono text-[11px] text-blue-700">
                      位值解析: {item.bitRange.preview}
                    </div>
                  )}
                  {item.inputText && (
                    <div className="mt-1 max-h-24 overflow-y-auto rounded border border-emerald-100 bg-emerald-50/70 px-2 py-1 font-mono text-[11px] text-emerald-800">
                      <span className="font-semibold">UTF-8输入: </span>
                      <span className="whitespace-pre-wrap break-words">{item.inputText}</span>
                    </div>
                  )}
                  {item.registerValues && <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{item.registerValues}</div>}
                </div>
              ),
            },
          ]}
          data={filteredModbusTransactions}
          rowKey={(item) => `${item.packetId}-${item.transactionId}-${item.kind}`}
          maxHeightClassName="max-h-[520px]"
          tableClassName="min-w-[1200px]"
          emptyText="暂无 Modbus 事务"
        />
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
