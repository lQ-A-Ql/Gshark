import { ShieldCheck } from "lucide-react";
import type { SMTPSession } from "../../core/types";
import { MetaChip } from "../ui";
import { SMTPSessionCommandTrace } from "./SMTPSessionCommandTrace";
import { SMTPSessionMessagePanel } from "./SMTPSessionMessagePanel";

interface SMTPSessionDetailsPanelProps {
  selectedSession: SMTPSession | null;
}

export function SMTPSessionDetailsPanel({ selectedSession }: SMTPSessionDetailsPanelProps) {
  return (
    <div className="space-y-4">
      <div className="gshark-tile border-slate-200 p-4">
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

      <SMTPSessionMessagePanel selectedSession={selectedSession} />
      <SMTPSessionCommandTrace selectedSession={selectedSession} />
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
              className="rounded-sm border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-700"
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
