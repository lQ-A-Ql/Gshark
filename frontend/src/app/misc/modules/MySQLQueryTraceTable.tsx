import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { MySQLSession } from "../../core/types";

interface MySQLQueryTraceTableProps {
  session: MySQLSession | null;
}

export function MySQLQueryTraceTable({ session }: MySQLQueryTraceTableProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="text-sm font-semibold text-slate-800">查询轨迹</div>
        <div className="text-[11px] text-slate-500">{session?.queries.length ?? 0} 条</div>
      </div>
      <DataTable
        data={session?.queries ?? []}
        rowKey={(row) => `${session?.streamId ?? "mysql"}-${row.packetId}-${row.command || "row"}`}
        maxHeightClassName="max-h-[420px]"
        wrapperClassName="border-slate-100 bg-white"
        headerClassName="bg-slate-50/95 text-slate-500"
        emptyText="暂无查询轨迹"
        rowClassName="hover:bg-emerald-50/40"
        columns={[
          {
            key: "packet",
            header: "请求包",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-700",
            render: (row) => row.packetId,
          },
          {
            key: "command",
            header: "命令",
            widthClassName: "w-24",
            cellClassName: "font-mono text-slate-700",
            render: (row) => row.command || "--",
          },
          {
            key: "response",
            header: "响应",
            widthClassName: "w-20",
            render: (row) =>
              row.responseKind ? (
                <span
                  className={`rounded-md px-2 py-1 text-[11px] font-semibold ${responseBadgeClass(row.responseKind)}`}
                >
                  {row.responseKind}
                </span>
              ) : (
                "--"
              ),
          },
          {
            key: "code",
            header: "代码",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-700",
            render: (row) => row.responseCode || "--",
          },
          {
            key: "database",
            header: "数据库",
            widthClassName: "w-24",
            cellClassName: "break-all font-mono text-slate-700",
            render: (row) => row.database || "--",
          },
          {
            key: "summary",
            header: "SQL / 摘要",
            cellClassName: "break-all font-mono text-[11px] text-slate-700",
            render: (row) => row.sql || row.responseSummary || "--",
          },
        ]}
      />
    </div>
  );
}

function responseBadgeClass(kind?: string) {
  switch (kind) {
    case "OK":
      return "bg-emerald-100 text-emerald-700";
    case "ERR":
      return "bg-rose-100 text-rose-700";
    case "RESULTSET":
      return "bg-sky-100 text-sky-700";
    default:
      return "bg-slate-100 text-slate-700";
  }
}
