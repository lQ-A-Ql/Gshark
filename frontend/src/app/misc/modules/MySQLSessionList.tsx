import type { MySQLSession } from "../../core/types";

interface MySQLSessionListProps {
  sessions: MySQLSession[];
  selectedStreamId?: number;
  hasCapture: boolean;
  onSelectSession: (streamId: number) => void;
}

export function MySQLSessionList({ sessions, selectedStreamId, hasCapture, onSelectSession }: MySQLSessionListProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-800">MySQL 会话列表</div>
        <div className="text-[11px] text-slate-500">{sessions.length} 条</div>
      </div>
      <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
        {sessions.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
            {hasCapture ? "当前筛选下没有匹配的 MySQL 会话" : "未加载抓包"}
          </div>
        ) : (
          sessions.map((item) => {
            const selected = selectedStreamId === item.streamId;
            return (
              <button
                key={`mysql-session-${item.streamId}`}
                type="button"
                onClick={() => onSelectSession(item.streamId)}
                className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                  selected
                    ? "border-emerald-400 bg-emerald-50 shadow-sm ring-2 ring-emerald-100"
                    : "border-slate-200 bg-white hover:border-emerald-200 hover:bg-emerald-50/40"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 font-mono text-[11px] font-semibold text-emerald-700">
                    MySQL #{item.streamId}
                  </span>
                  {item.username ? (
                    <span className="rounded-md bg-emerald-100 px-2 py-1 text-[11px] font-semibold text-emerald-700">
                      登录
                    </span>
                  ) : null}
                  {item.errCount > 0 ? (
                    <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">
                      错误 {item.errCount}
                    </span>
                  ) : null}
                  {item.resultsetCount > 0 ? (
                    <span className="rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">
                      结果集 {item.resultsetCount}
                    </span>
                  ) : null}
                </div>
                <div className="mt-2 break-all font-medium text-slate-800">{renderMySQLSessionTitle(item)}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                  <span>查询 {item.queryCount}</span>
                  {item.username ? <span>用户 {item.username}</span> : null}
                  {item.database ? <span>数据库 {item.database}</span> : null}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

export function renderMySQLSessionTitle(session: MySQLSession) {
  const left = session.client
    ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}`
    : `stream #${session.streamId}`;
  const right = session.server
    ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}`
    : "MySQL server";
  return `${left} → ${right}`;
}
