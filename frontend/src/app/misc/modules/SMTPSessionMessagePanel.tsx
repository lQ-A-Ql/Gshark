import { Paperclip } from "lucide-react";
import type { SMTPSession } from "../../core/types";

interface SMTPSessionMessagePanelProps {
  selectedSession: SMTPSession | null;
}

export function SMTPSessionMessagePanel({ selectedSession }: SMTPSessionMessagePanelProps) {
  return (
    <div className="gshark-tile border-slate-200 p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="text-sm font-semibold text-slate-800">邮件重建</div>
        <div className="text-[11px] text-slate-500">{selectedSession?.messages?.length ?? 0} 条</div>
      </div>
      {!selectedSession || (selectedSession.messages?.length ?? 0) === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
          该 SMTP 会话暂未重建出邮件正文。
        </div>
      ) : (
        <div className="max-h-[420px] space-y-3 overflow-auto pr-1">
          {(selectedSession.messages ?? []).map((message) => (
            <div
              key={`${selectedSession.streamId}-${message.sequence}`}
              className="gshark-tile border-slate-200 bg-slate-50/60 p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-sm border border-sky-200 bg-sky-50 px-2 py-1 text-[11px] font-semibold text-sky-700">
                  邮件 #{message.sequence}
                </span>
                {message.subject ? (
                  <span className="text-sm font-semibold text-slate-800">{message.subject}</span>
                ) : (
                  <span className="text-sm text-slate-500">(无主题)</span>
                )}
                {(message.attachmentNames?.length ?? 0) > 0 ? (
                  <span className="inline-flex items-center gap-1 rounded-md bg-sky-100 px-2 py-1 text-[11px] font-semibold text-sky-700">
                    <Paperclip className="h-3.5 w-3.5" />
                    {message.attachmentNames?.length} 个附件线索
                  </span>
                ) : null}
              </div>
              <div className="mt-2 grid gap-3 md:grid-cols-2">
                <MiniField label="From" value={message.from || message.mailFrom || "--"} />
                <MiniField label="To" value={message.to || message.rcptTo?.join(", ") || "--"} />
                <MiniField label="Date" value={message.date || "--"} />
                <MiniField label="Content-Type" value={message.contentType || "--"} />
              </div>
              {(message.attachmentNames?.length ?? 0) > 0 && (
                <div className="mt-3">
                  <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                    附件文件名
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {message.attachmentNames?.map((name) => (
                      <span
                        key={`${message.sequence}-${name}`}
                        className="rounded-sm border border-sky-200 bg-sky-50 px-2 py-1 font-mono text-[11px] text-sky-700"
                      >
                        {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <div className="mt-3 rounded-sm border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-600">
                {message.bodyPreview || "无正文预览"}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function MiniField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-slate-200 bg-slate-50 px-3 py-2">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 break-all text-[12px] text-slate-700">{value}</div>
    </div>
  );
}
