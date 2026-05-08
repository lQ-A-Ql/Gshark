import type { SMTPSession } from "../../core/types";
import { renderSMTPSessionTitle } from "./SMTPSessionAnalysisUtils";

interface SMTPSessionListProps {
  hasCapture: boolean;
  sessions: SMTPSession[];
  selectedSession: SMTPSession | null;
  messageCount: number;
  onSelectSession: (streamId: number) => void;
}

export function SMTPSessionList({
  hasCapture,
  sessions,
  selectedSession,
  messageCount,
  onSelectSession,
}: SMTPSessionListProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-800">SMTP 会话列表</div>
        <div className="text-[11px] text-slate-500">
          {sessions.length} 条 / 邮件 {messageCount}
        </div>
      </div>
      <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
        {sessions.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
            {hasCapture ? "当前筛选下没有匹配的 SMTP 会话" : "未加载抓包"}
          </div>
        ) : (
          sessions.map((item) => {
            const selected = selectedSession?.streamId === item.streamId;
            return (
              <button
                key={`smtp-session-${item.streamId}`}
                type="button"
                onClick={() => onSelectSession(item.streamId)}
                className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                  selected
                    ? "border-sky-400 bg-sky-50 shadow-sm ring-2 ring-sky-100"
                    : "border-slate-200 bg-white hover:border-sky-200 hover:bg-sky-50/40"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-sky-200 bg-sky-50 px-2 py-1 font-mono text-[11px] font-semibold text-sky-700">
                    SMTP #{item.streamId}
                  </span>
                  {item.authUsername || (item.authMechanisms?.length ?? 0) > 0 ? (
                    <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">
                      认证
                    </span>
                  ) : null}
                  {(item.attachmentHints ?? 0) > 0 ? (
                    <span className="rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">
                      附件 {item.attachmentHints}
                    </span>
                  ) : null}
                  {item.possibleCleartext ? (
                    <span className="rounded-md bg-amber-100 px-2 py-1 text-[11px] font-semibold text-amber-700">
                      明文凭据风险
                    </span>
                  ) : null}
                </div>
                <div className="mt-2 break-all font-medium text-slate-800">{renderSMTPSessionTitle(item)}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                  <span>命令 {item.commandCount}</span>
                  <span>邮件 {item.messageCount}</span>
                  {(item.mailFrom?.length ?? 0) > 0 ? <span>发件人 {item.mailFrom?.length}</span> : null}
                  {(item.rcptTo?.length ?? 0) > 0 ? <span>收件人 {item.rcptTo?.length}</span> : null}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
