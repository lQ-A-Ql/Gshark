import {
  AnalysisBadge,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  type AnalysisTone,
} from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { VehicleAnalysis as VehicleAnalysisData } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";

const UDS_NEGATIVE_RESPONSE_CN: Record<string, string> = {
  "0x10": "一般拒绝",
  "0x11": "服务不支持",
  "0x12": "子功能不支持",
  "0x13": "消息长度错误",
  "0x14": "响应过长",
  "0x22": "条件不满足",
  "0x24": "请求序列错误",
  "0x25": "拒绝-无子网",
  "0x31": "请求超出范围",
  "0x33": "安全访问被拒",
  "0x35": "密钥无效",
  "0x36": "尝试次数超限",
  "0x37": "延时未到",
  "0x70": "上传下载不接受",
  "0x71": "传输数据暂停",
  "0x72": "一般编程失败",
  "0x73": "错误的区块序列",
  "0x74": "响应挂起",
  "0x75": "不支持的地址",
  "0x76": "不支持的长度",
  "0x77": "响应未发送",
  "0x78": "不支持的模式",
  "0x7e": "会话不支持子功能",
  "0x7f": "会话不支持服务",
};

const UDS_STATUS_OPTIONS = [
  { value: "all", label: "全部" },
  { value: "positive", label: "正常响应" },
  { value: "negative", label: "负响应" },
  { value: "orphan-response", label: "孤立响应" },
  { value: "request-only", label: "仅请求" },
];

type UdsTransaction = VehicleAnalysisData["uds"]["transactions"][number];

interface VehicleUdsTransactionsPanelProps {
  transactions: UdsTransaction[];
  filteredTransactions: UdsTransaction[];
  statusFilter: string;
  onStatusFilterChange: (value: string) => void;
}

export function VehicleUdsTransactionsPanel({
  transactions,
  filteredTransactions,
  statusFilter,
  onStatusFilterChange,
}: VehicleUdsTransactionsPanelProps) {
  return (
    <Panel title={`UDS 配对事务预览 (${filteredTransactions.length})`} className="mt-0">
      <div className="mb-3 flex flex-wrap gap-2">
        {UDS_STATUS_OPTIONS.map((opt) => {
          const active = statusFilter === opt.value;
          const count =
            opt.value === "all" ? transactions.length : transactions.filter((t) => t.status === opt.value).length;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onStatusFilterChange(opt.value)}
              className={cn(
                "border px-3 py-1 text-[11px] font-medium transition-all",
                active
                  ? "border-emerald-200 bg-emerald-100 text-emerald-700"
                  : "border-slate-200 bg-slate-50/70 text-slate-500 hover:border-emerald-200 hover:text-emerald-700",
              )}
            >
              {opt.label} · {count}
            </button>
          );
        })}
      </div>
      <DataTable
        columns={[
          {
            key: "req",
            header: "请求包",
            widthClassName: "w-16",
            cellClassName: "font-mono text-slate-500",
            render: (item) => item.requestPacketId || "--",
          },
          {
            key: "resp",
            header: "响应包",
            widthClassName: "w-16",
            cellClassName: "font-mono text-slate-500",
            render: (item) => item.responsePacketId || "--",
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-36",
            cellClassName: "font-mono text-[11px]",
            render: (item) => [item.requestTime, item.responseTime].filter(Boolean).join(" → ") || "--",
          },
          {
            key: "addr",
            header: "地址",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (item) => [item.sourceAddress, item.targetAddress].filter(Boolean).join(" → ") || "--",
          },
          {
            key: "service",
            header: "服务",
            widthClassName: "w-28",
            render: (item) => (
              <span className="font-mono text-[12px]">
                {[item.serviceId, item.serviceName].filter(Boolean).join(" ") || "--"}
              </span>
            ),
          },
          {
            key: "object",
            header: "对象",
            widthClassName: "w-24",
            cellClassName: "font-mono text-[11px]",
            render: (item) => item.dataIdentifier || item.dtc || item.subFunction || "--",
          },
          {
            key: "status",
            header: "状态",
            widthClassName: "w-32",
            render: (item) => {
              const tone = udsStatusTone(item.status);
              const label = item.negativeCode
                ? `${item.status} / ${udsNegativeResponseCN(item.negativeCode)}`
                : item.status || "--";
              return <AnalysisBadge tone={tone}>{label}</AnalysisBadge>;
            },
          },
          {
            key: "latency",
            header: "耗时(ms)",
            widthClassName: "w-20",
            cellClassName: "font-mono",
            render: (item) => (item.latencyMs != null ? item.latencyMs.toFixed(1) : "--"),
          },
          {
            key: "summary",
            header: "摘要",
            render: (item) => (
              <span className="text-[12px]">{item.responseSummary || item.requestSummary || "--"}</span>
            ),
          },
          {
            key: "actions",
            header: "定位",
            widthClassName: "w-16",
            render: (item) =>
              item.requestPacketId ? <EvidenceActions packetId={item.requestPacketId} preferredProtocol="TCP" /> : "--",
          },
        ]}
        data={filteredTransactions}
        rowKey={(item, idx) => `${item.requestPacketId}-${item.responsePacketId}-${idx}`}
        maxHeightClassName="max-h-[520px]"
        tableClassName="min-w-[1100px]"
        emptyText="暂无 UDS 配对事务"
      />
    </Panel>
  );
}

function udsNegativeResponseCN(code: string): string {
  const lower = (code || "").toLowerCase();
  return UDS_NEGATIVE_RESPONSE_CN[lower] || code || "";
}

function udsStatusTone(status: string): AnalysisTone {
  switch (status) {
    case "positive":
      return "emerald";
    case "negative":
      return "rose";
    case "orphan-response":
      return "amber";
    case "request-only":
      return "slate";
    default:
      return "slate";
  }
}
