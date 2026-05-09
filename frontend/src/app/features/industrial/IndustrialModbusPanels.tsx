import { AlertTriangle, Workflow } from "lucide-react";
import {
  AnalysisBadge,
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  type AnalysisTone,
} from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { ModbusDecodedInput, ModbusSuspiciousWrite, ModbusTransaction } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";

interface IndustrialModbusPanelsProps {
  suspiciousWrites: ModbusSuspiciousWrite[];
  decodedInputs: ModbusDecodedInput[];
  transactions: ModbusTransaction[];
  unitOptions: string[];
  functionOptions: string[];
  unitFilter: string;
  functionFilter: string;
  onUnitFilterChange: (value: string) => void;
  onFunctionFilterChange: (value: string) => void;
}

export function IndustrialModbusPanels({
  suspiciousWrites,
  decodedInputs,
  transactions,
  unitOptions,
  functionOptions,
  unitFilter,
  functionFilter,
  onUnitFilterChange,
  onFunctionFilterChange,
}: IndustrialModbusPanelsProps) {
  return (
    <>
      {suspiciousWrites.length > 0 && <ModbusSuspiciousWritesPanel suspiciousWrites={suspiciousWrites} />}
      {decodedInputs.length > 0 && <ModbusDecodedInputsPanel decodedInputs={decodedInputs} />}
      <ModbusTransactionsPanel
        transactions={transactions}
        unitOptions={unitOptions}
        functionOptions={functionOptions}
        unitFilter={unitFilter}
        functionFilter={functionFilter}
        onUnitFilterChange={onUnitFilterChange}
        onFunctionFilterChange={onFunctionFilterChange}
      />
    </>
  );
}

function ModbusSuspiciousWritesPanel({ suspiciousWrites }: { suspiciousWrites: ModbusSuspiciousWrite[] }) {
  return (
    <Panel title={`Modbus 可疑写操作 (${suspiciousWrites.length})`} className="mt-4">
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
        data={suspiciousWrites}
        rowKey={(_sw, idx) => `sw-${idx}`}
        maxHeightClassName="max-h-[420px]"
        tableClassName="min-w-[920px]"
        emptyText="暂无可疑写操作"
      />
    </Panel>
  );
}

function ModbusDecodedInputsPanel({ decodedInputs }: { decodedInputs: ModbusDecodedInput[] }) {
  return (
    <Panel title={`Modbus UTF-8 输入重组 (${decodedInputs.length})`} className="mt-4">
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
        data={decodedInputs}
        rowKey={(item, idx) => `decoded-input-${item.startPacketId}-${item.endPacketId}-${idx}`}
        maxHeightClassName="max-h-[420px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无可重组 UTF-8 输入"
      />
    </Panel>
  );
}

function ModbusTransactionsPanel({
  transactions,
  unitOptions,
  functionOptions,
  unitFilter,
  functionFilter,
  onUnitFilterChange,
  onFunctionFilterChange,
}: Omit<IndustrialModbusPanelsProps, "suspiciousWrites" | "decodedInputs">) {
  return (
    <Panel title={`Modbus 事务明细 (${transactions.length})`} className="mt-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-medium text-slate-500">Unit ID:</span>
        {unitOptions.map((u) => (
          <button
            key={u}
            type="button"
            onClick={() => onUnitFilterChange(u)}
            className={cn(
              "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
              unitFilter === u
                ? "border-blue-200 bg-blue-100 text-blue-700"
                : "border-slate-200 bg-white/80 text-slate-500 hover:border-blue-200",
            )}
          >
            {u === "all" ? "全部" : u}
          </button>
        ))}
        <span className="ml-3 text-[11px] font-medium text-slate-500">功能码:</span>
        {functionOptions.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => onFunctionFilterChange(f)}
            className={cn(
              "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
              functionFilter === f
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
        data={transactions}
        rowKey={(item) => `${item.packetId}-${item.transactionId}-${item.kind}`}
        maxHeightClassName="max-h-[520px]"
        tableClassName="min-w-[1200px]"
        emptyText="暂无 Modbus 事务"
      />
    </Panel>
  );
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
