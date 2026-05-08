import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { SMTPSession } from "../../core/types";

interface SMTPSessionCommandTraceProps {
  selectedSession: SMTPSession | null;
}

export function SMTPSessionCommandTrace({ selectedSession }: SMTPSessionCommandTraceProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="text-sm font-semibold text-slate-800">命令轨迹</div>
        <div className="text-[11px] text-slate-500">{selectedSession?.commands?.length ?? 0} 条</div>
      </div>
      <DataTable
        data={selectedSession?.commands ?? []}
        rowKey={(command) =>
          `${selectedSession?.streamId ?? "smtp"}-${command.packetId}-${command.summary || command.command || command.statusCode || "row"}`
        }
        maxHeightClassName="max-h-[320px]"
        wrapperClassName="border-slate-100 bg-white"
        headerClassName="bg-slate-50/95 text-slate-500"
        emptyText="暂无命令轨迹"
        rowClassName="hover:bg-sky-50/40"
        columns={[
          {
            key: "packet",
            header: "包号",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-700",
            render: (command) => command.packetId,
          },
          {
            key: "direction",
            header: "方向",
            widthClassName: "w-20",
            render: (command) => command.direction || "--",
          },
          {
            key: "command",
            header: "命令",
            widthClassName: "w-24",
            cellClassName: "font-mono text-slate-700",
            render: (command) => command.command || "--",
          },
          {
            key: "status",
            header: "状态码",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-700",
            render: (command) => command.statusCode || "--",
          },
          {
            key: "summary",
            header: "摘要",
            cellClassName: "break-all text-slate-700",
            render: (command) => command.summary || command.argument || "--",
          },
        ]}
      />
    </div>
  );
}
