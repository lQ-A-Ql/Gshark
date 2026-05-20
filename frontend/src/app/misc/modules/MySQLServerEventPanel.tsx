import { TriangleAlert } from "lucide-react";
import type { MySQLSession } from "../../core/types";

interface MySQLServerEventPanelProps {
  session: MySQLSession | null;
}

export function MySQLServerEventPanel({ session }: MySQLServerEventPanelProps) {
  return (
    <div className="gshark-tile border-slate-200 p-4">
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
                <span className="rounded-sm border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
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
  );
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
