import type { MySQLSession } from "../../core/types";
import { MetaChip } from "../ui";

interface MySQLSessionOverviewPanelProps {
  session: MySQLSession | null;
}

export function MySQLSessionOverviewPanel({ session }: MySQLSessionOverviewPanelProps) {
  return (
    <div className="gshark-tile border-slate-200 p-4">
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
