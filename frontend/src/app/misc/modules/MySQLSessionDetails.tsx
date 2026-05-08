import { TriangleAlert } from "lucide-react";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { MySQLSession } from "../../core/types";
import { MetaChip } from "../ui";

interface MySQLSessionDetailsProps {
  session: MySQLSession | null;
}

export function MySQLSessionDetails({ session }: MySQLSessionDetailsProps) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-slate-800">会话详情</div>
            <div className="text-[12px] text-slate-500">查看握手版本、登录用户名、默认库、认证插件与查询统计。</div>
          </div>
        </div>
        {!session ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            请选择左侧一条 MySQL 会话查看详情。
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <MetaChip label="Stream" value={session.streamId} color="sky" />
              <MetaChip
                label="Server"
                value={session.server ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}` : "--"}
                color="slate"
              />
              <MetaChip
                label="Client"
                value={session.client ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}` : "--"}
                color="slate"
              />
              <MetaChip label="Version" value={session.serverVersion || "--"} color="slate" />
              <MetaChip label="Plugin" value={session.authPlugin || "--"} color="slate" />
              <MetaChip
                label="登录状态"
                value={session.loginPacketId ? (session.loginSuccess ? "成功" : "失败/未知") : "未识别"}
                color={session.loginSuccess ? "emerald" : session.loginPacketId ? "rose" : "slate"}
              />
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <InfoBlock
                title="用户名"
                values={session.username ? [session.username] : []}
                empty="未识别到登录用户名"
                tone="emerald"
              />
              <InfoBlock
                title="数据库"
                values={session.database ? [session.database] : []}
                empty="未识别默认数据库"
                tone="sky"
              />
              <InfoBlock title="命令类型" values={session.commandTypes ?? []} empty="暂无命令类型" tone="slate" />
              <InfoBlock title="会话说明" values={session.notes ?? []} empty="暂无额外说明" tone="slate" />
            </div>
          </div>
        )}
      </div>

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

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div className="text-sm font-semibold text-slate-800">服务端事件</div>
          <div className="text-[11px] text-slate-500">{session?.serverEvents.length ?? 0} 条</div>
        </div>
        {!session || session.serverEvents.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            暂无服务端事件摘要
          </div>
        ) : (
          <div className="max-h-[280px] space-y-2 overflow-auto pr-1">
            {session.serverEvents.map((event) => (
              <div
                key={`${session.streamId}-${event.packetId}-${event.kind || "evt"}`}
                className="rounded-lg border border-slate-200 bg-slate-50/60 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-emerald-200 bg-white px-2 py-1 text-[11px] font-semibold text-emerald-700">
                    帧 #{event.packetId}
                  </span>
                  <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${eventBadgeClass(event.kind)}`}>
                    {event.kind || "UNKNOWN"}
                  </span>
                  {event.code ? <span className="font-mono text-[11px] text-slate-500">code {event.code}</span> : null}
                  {event.sequence !== undefined ? (
                    <span className="font-mono text-[11px] text-slate-500">seq {event.sequence}</span>
                  ) : null}
                </div>
                <div className="mt-2 break-all text-[12px] text-slate-600">{event.summary || "--"}</div>
              </div>
            ))}
          </div>
        )}
        {session && session.errCount > 0 && (
          <div className="mt-4 rounded-lg border border-rose-200 bg-rose-50 px-3 py-3 text-[12px] text-rose-700">
            <div className="flex items-center gap-2 font-semibold">
              <TriangleAlert className="h-4 w-4" />
              错误响应观察
            </div>
            <div className="mt-2 leading-relaxed">
              该会话包含 {session.errCount} 条 MySQL 错误响应，建议结合查询轨迹排查失败登录、权限问题、SQL
              语法错误或探测行为。
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function InfoBlock({
  title,
  values,
  empty,
  tone = "slate",
}: {
  title: string;
  values?: string[];
  empty: string;
  tone?: "slate" | "emerald" | "sky";
}) {
  const toneClass =
    tone === "emerald"
      ? "border-emerald-200 bg-emerald-50/40"
      : tone === "sky"
        ? "border-sky-200 bg-sky-50/40"
        : "border-slate-200 bg-slate-50/70";
  return (
    <div className={`rounded-lg border p-3 ${toneClass}`}>
      <div className="mb-2 text-[12px] font-semibold text-slate-700">{title}</div>
      {values && values.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <span
              key={`${title}-${value}`}
              className="rounded-md border border-white/80 bg-white px-2 py-1 font-mono text-[11px] text-slate-700 shadow-sm"
            >
              {value}
            </span>
          ))}
        </div>
      ) : (
        <div className="text-[12px] text-slate-500">{empty}</div>
      )}
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

function eventBadgeClass(kind?: string) {
  switch (kind) {
    case "HANDSHAKE":
      return "bg-violet-100 text-violet-700";
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
