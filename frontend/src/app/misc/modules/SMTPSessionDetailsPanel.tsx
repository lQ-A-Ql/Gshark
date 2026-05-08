import { Paperclip, ShieldCheck } from "lucide-react";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { SMTPSession } from "../../core/types";
import { MetaChip } from "../ui";

interface SMTPSessionDetailsPanelProps {
  selectedSession: SMTPSession | null;
}

export function SMTPSessionDetailsPanel({ selectedSession }: SMTPSessionDetailsPanelProps) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-slate-800">会话详情</div>
            <div className="text-[12px] text-slate-500">查看认证、MAIL FROM / RCPT TO、状态提示与明文风险。</div>
          </div>
        </div>
        {!selectedSession ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            请选择左侧的一条 SMTP 会话查看详情。
          </div>
        ) : (
          <SMTPSessionOverview selectedSession={selectedSession} />
        )}
      </div>

      <SMTPMessageRebuildPanel selectedSession={selectedSession} />
      <SMTPCommandTracePanel selectedSession={selectedSession} />
    </div>
  );
}

function SMTPSessionOverview({ selectedSession }: { selectedSession: SMTPSession }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <MetaChip label="Stream" value={selectedSession.streamId} color="sky" />
        <MetaChip
          label="客户端"
          value={
            selectedSession.client
              ? `${selectedSession.client}${selectedSession.clientPort ? `:${selectedSession.clientPort}` : ""}`
              : "--"
          }
          color="slate"
        />
        <MetaChip
          label="服务端"
          value={
            selectedSession.server
              ? `${selectedSession.server}${selectedSession.serverPort ? `:${selectedSession.serverPort}` : ""}`
              : "--"
          }
          color="slate"
        />
        <MetaChip label="HELO" value={selectedSession.helo || "--"} color="slate" />
        <MetaChip
          label="机制"
          value={selectedSession.authMechanisms?.join(", ") || "--"}
          color={(selectedSession.authMechanisms?.length ?? 0) > 0 ? "rose" : "slate"}
        />
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <InfoBlock
          title="认证用户名"
          values={selectedSession.authUsername ? [selectedSession.authUsername] : []}
          empty="未解析到用户名"
          tone="rose"
        />
        <InfoBlock title="状态提示" values={selectedSession.statusHints ?? []} empty="暂无状态提示" tone="slate" />
        <InfoBlock title="MAIL FROM" values={selectedSession.mailFrom ?? []} empty="无 MAIL FROM" tone="sky" />
        <InfoBlock title="RCPT TO" values={selectedSession.rcptTo ?? []} empty="无 RCPT TO" tone="sky" />
      </div>

      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[12px] text-slate-600">
        <div className="flex items-center gap-2 font-semibold text-slate-700">
          <ShieldCheck className="h-4 w-4 text-sky-600" />
          认证观察
        </div>
        <div className="mt-2 leading-relaxed">
          {selectedSession.authUsername || (selectedSession.authMechanisms?.length ?? 0) > 0
            ? `${selectedSession.authPasswordSeen ? "检测到密码材料经过明文或可逆 Base64 传输。" : "检测到 SMTP AUTH 协商，但未直接看到密码正文。"}${selectedSession.possibleCleartext ? " 建议结合 STARTTLS / TLS 解密确认是否存在明文暴露。" : ""}`
            : "该会话未检测到明显的 SMTP AUTH 材料，更偏向普通投递或服务器响应流。"}
        </div>
      </div>
    </div>
  );
}

function SMTPMessageRebuildPanel({ selectedSession }: { selectedSession: SMTPSession | null }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
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
              className="rounded-xl border border-slate-200 bg-slate-50/60 p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-sky-200 bg-white px-2 py-1 text-[11px] font-semibold text-sky-700">
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
                        className="rounded-md border border-sky-200 bg-white px-2 py-1 font-mono text-[11px] text-sky-700"
                      >
                        {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <div className="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-600">
                {message.bodyPreview || "无正文预览"}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SMTPCommandTracePanel({ selectedSession }: { selectedSession: SMTPSession | null }) {
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

function InfoBlock({
  title,
  values,
  empty,
  tone = "slate",
}: {
  title: string;
  values?: string[];
  empty: string;
  tone?: "slate" | "rose" | "sky";
}) {
  const toneClass =
    tone === "rose"
      ? "border-rose-200 bg-rose-50/40"
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

function MiniField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 break-all text-[12px] text-slate-700">{value}</div>
    </div>
  );
}
