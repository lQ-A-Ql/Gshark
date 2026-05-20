import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { HTTPLoginAnalysis } from "../../core/types";

type HTTPLoginAttempt = HTTPLoginAnalysis["attempts"][number];

interface HTTPLoginAttemptTableProps {
  attempts: HTTPLoginAttempt[];
}

export function HTTPLoginAttemptTable({ attempts }: HTTPLoginAttemptTableProps) {
  return (
    <div className="gshark-tile overflow-hidden border-slate-200">
      <div className="gshark-tile-header flex items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/80 px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-slate-800">认证尝试明细</div>
          <div className="mt-0.5 text-[11px] text-slate-500">按包号串联请求、响应、凭据线索与判定原因。</div>
        </div>
        <span className="shrink-0 rounded-full border border-cyan-200 bg-cyan-50 px-2.5 py-1 text-[11px] font-semibold text-cyan-700">
          {attempts.length} 条
        </span>
      </div>
      <DataTable
        data={attempts}
        rowKey={(item) => `${item.packetId}-${item.responsePacketId || 0}`}
        maxHeightClassName="max-h-[460px]"
        tableClassName="min-w-[1040px] border-separate border-spacing-0"
        wrapperClassName="gshark-tile-table rounded-none border-0"
        headerClassName="gshark-tile-header z-10 bg-slate-50/80 text-[11px] uppercase tracking-[0.12em]"
        headerCellClassName="py-3 font-semibold"
        emptyText="暂无认证尝试"
        rowClassName="odd:bg-transparent even:bg-slate-50/45 hover:bg-cyan-50/45"
        cellClassName="py-3"
        columns={[
          {
            key: "request",
            header: "请求包",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] font-semibold text-slate-800",
            render: (item) => `#${item.packetId}`,
          },
          {
            key: "response",
            header: "响应包",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-600",
            render: (item) => (item.responsePacketId ? `#${item.responsePacketId}` : "--"),
          },
          {
            key: "result",
            header: "结果",
            widthClassName: "w-[104px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap",
            render: (item) => (
              <span className={attemptBadge(item.result, item.possibleBruteforce)}>
                {renderAttemptLabel(item.result, item.possibleBruteforce)}
              </span>
            ),
          },
          {
            key: "status",
            header: "状态码",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-700",
            render: (item) => item.statusCode || "--",
          },
          {
            key: "username",
            header: "用户名",
            widthClassName: "w-[140px]",
            headerClassName: "whitespace-nowrap",
            render: (item) => (
              <div
                className="max-w-[128px] truncate font-mono text-[11px] text-slate-700"
                title={item.username || "--"}
              >
                {item.username || "--"}
              </div>
            ),
          },
          {
            key: "keys",
            header: "参数键",
            widthClassName: "w-[170px]",
            headerClassName: "whitespace-nowrap",
            render: (item) => {
              const keys = (item.requestKeys ?? []).join(", ") || "--";
              return (
                <div className="max-w-[158px] truncate font-mono text-[11px] text-slate-600" title={keys}>
                  {keys}
                </div>
              );
            },
          },
          {
            key: "reason",
            header: "原因",
            widthClassName: "w-[190px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "text-[12px] leading-relaxed text-slate-700",
            render: (item) => item.reason || "--",
          },
          {
            key: "preview",
            header: "请求 / 响应预览",
            headerClassName: "min-w-[300px] whitespace-nowrap",
            render: (item) => (
              <div className="space-y-1.5">
                <PreviewLine label="REQ" value={item.requestPreview || "--"} tone="sky" />
                {item.responsePreview ? <PreviewLine label="RESP" value={item.responsePreview} tone="slate" /> : null}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
}

function PreviewLine({ label, value, tone }: { label: string; value: string; tone: "sky" | "slate" }) {
  return (
    <div
      className={`flex min-w-0 items-start gap-2 rounded-lg border px-2.5 py-2 ${
        tone === "sky" ? "border-sky-100 bg-sky-50/70 text-sky-900" : "border-slate-100 bg-slate-50 text-slate-700"
      }`}
    >
      <span
        className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-[0.12em] ${
          tone === "sky" ? "bg-sky-100 text-sky-700" : "bg-slate-200/70 text-slate-600"
        }`}
      >
        {label}
      </span>
      <span className="min-w-0 break-all font-mono text-[11px] leading-relaxed">{value}</span>
    </div>
  );
}

function attemptBadge(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "rounded border border-rose-200 bg-rose-50 px-2 py-0.5 text-rose-700";
  switch (result) {
    case "success":
      return "rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-emerald-700";
    case "failure":
      return "rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-amber-700";
    default:
      return "rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-slate-700";
  }
}

function renderAttemptLabel(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "疑似爆破";
  switch (result) {
    case "success":
      return "成功";
    case "failure":
      return "失败";
    default:
      return "待确认";
  }
}
