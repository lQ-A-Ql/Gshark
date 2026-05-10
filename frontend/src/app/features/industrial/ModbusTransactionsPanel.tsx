import {
  AnalysisBadge,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  type AnalysisTone,
} from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { ModbusTransaction } from "../../core/types";

interface ModbusTransactionsPanelProps {
  transactions: ModbusTransaction[];
  unitOptions: string[];
  functionOptions: string[];
  unitFilter: string;
  functionFilter: string;
  onUnitFilterChange: (value: string) => void;
  onFunctionFilterChange: (value: string) => void;
}

export function ModbusTransactionsPanel({
  transactions,
  unitOptions,
  functionOptions,
  unitFilter,
  functionFilter,
  onUnitFilterChange,
  onFunctionFilterChange,
}: ModbusTransactionsPanelProps) {
  return (
    <Panel title={`Modbus 事务明细 (${transactions.length})`} className="mt-4">
      <ModbusTransactionFilters
        unitOptions={unitOptions}
        functionOptions={functionOptions}
        unitFilter={unitFilter}
        functionFilter={functionFilter}
        onUnitFilterChange={onUnitFilterChange}
        onFunctionFilterChange={onFunctionFilterChange}
      />
      <DataTable
        columns={[
          {
            key: "packet",
            header: "包号",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-500",
            render: (item) => item.packetId,
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (item) => item.time || "--",
          },
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
          {
            key: "kind",
            header: "类型",
            widthClassName: "w-20",
            render: (item) => (
              <AnalysisBadge tone={toneForIndustrialTransactionKind(item.kind)}>{item.kind}</AnalysisBadge>
            ),
          },
          {
            key: "unit",
            header: "Unit",
            widthClassName: "w-24",
            cellClassName: "font-mono",
            render: (item) => item.unitId || "--",
          },
          {
            key: "reference",
            header: "引用",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (item) => item.reference || "--",
          },
          {
            key: "quantity",
            header: "数量",
            widthClassName: "w-20",
            cellClassName: "font-mono",
            render: (item) => item.quantity || "--",
          },
          {
            key: "latency",
            header: "耗时",
            widthClassName: "w-20",
            cellClassName: "font-mono",
            render: (item) => item.responseTime || "--",
          },
          {
            key: "summary",
            header: "摘要",
            render: (item) => <ModbusTransactionSummary transaction={item} />,
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

function ModbusTransactionFilters({
  unitOptions,
  functionOptions,
  unitFilter,
  functionFilter,
  onUnitFilterChange,
  onFunctionFilterChange,
}: Omit<ModbusTransactionsPanelProps, "transactions">) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2">
      <span className="text-[11px] font-medium text-slate-500">Unit ID:</span>
      {unitOptions.map((unit) => (
        <button
          key={unit}
          type="button"
          onClick={() => onUnitFilterChange(unit)}
          className={cn(
            "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
            unitFilter === unit
              ? "border-blue-200 bg-blue-100 text-blue-700"
              : "border-slate-200 bg-white/80 text-slate-500 hover:border-blue-200",
          )}
        >
          {unit === "all" ? "全部" : unit}
        </button>
      ))}
      <span className="ml-3 text-[11px] font-medium text-slate-500">功能码:</span>
      {functionOptions.map((functionCode) => (
        <button
          key={functionCode}
          type="button"
          onClick={() => onFunctionFilterChange(functionCode)}
          className={cn(
            "rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all",
            functionFilter === functionCode
              ? "border-blue-200 bg-blue-100 text-blue-700"
              : "border-slate-200 bg-white/80 text-slate-500 hover:border-blue-200",
          )}
        >
          {functionCode === "all" ? "全部" : functionCode}
        </button>
      ))}
    </div>
  );
}

function ModbusTransactionSummary({ transaction }: { transaction: ModbusTransaction }) {
  return (
    <div>
      <div>{transaction.summary || "--"}</div>
      {transaction.bitRange?.preview && (
        <div className="mt-1 break-all font-mono text-[11px] text-blue-700">
          位值解析: {transaction.bitRange.preview}
        </div>
      )}
      {transaction.inputText && (
        <div className="mt-1 max-h-24 overflow-y-auto rounded border border-emerald-100 bg-emerald-50/70 px-2 py-1 font-mono text-[11px] text-emerald-800">
          <span className="font-semibold">UTF-8输入: </span>
          <span className="whitespace-pre-wrap break-words">{transaction.inputText}</span>
        </div>
      )}
      {transaction.registerValues && (
        <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{transaction.registerValues}</div>
      )}
    </div>
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
