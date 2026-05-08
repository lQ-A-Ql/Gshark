import { AlertTriangle, ShieldCheck } from "lucide-react";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { HTTPLoginAnalysis, HTTPLoginEndpoint } from "../../core/types";
import { MetaChip } from "../ui";

type HTTPLoginAttempt = HTTPLoginAnalysis["attempts"][number];

interface HTTPLoginDetailsPanelProps {
  selectedEndpoint: HTTPLoginEndpoint | null;
  attempts: HTTPLoginAttempt[];
  bruteforceCount: number;
  successCount: number;
}

export function HTTPLoginDetailsPanel({
  selectedEndpoint,
  attempts,
  bruteforceCount,
  successCount,
}: HTTPLoginDetailsPanelProps) {
  return (
    <div className="space-y-4">
      <HTTPLoginEndpointDetails selectedEndpoint={selectedEndpoint} />
      <HTTPLoginAttemptTable attempts={attempts} />
      {bruteforceCount > 0 && <HTTPLoginBruteforceAlert bruteforceCount={bruteforceCount} />}
      {successCount > 0 && <HTTPLoginSuccessHint />}
    </div>
  );
}

function HTTPLoginEndpointDetails({ selectedEndpoint }: { selectedEndpoint: HTTPLoginEndpoint | null }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-slate-800">端点详情</div>
          <div className="text-[12px] text-slate-500">聚合查看参数键、状态码分布、响应信号与疑似爆破线索。</div>
        </div>
      </div>
      {!selectedEndpoint ? (
        <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
          请选择左侧的一个认证端点查看详情。
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <MetaChip label="Method" value={selectedEndpoint.method || "HTTP"} color="sky" />
            <MetaChip label="Host" value={selectedEndpoint.host || "--"} color="slate" />
            <MetaChip label="Path" value={selectedEndpoint.path || "/"} color="slate" />
            <MetaChip label="尝试" value={selectedEndpoint.attemptCount} color="slate" />
            <MetaChip label="Set-Cookie" value={selectedEndpoint.setCookieCount || 0} color="emerald" />
            <MetaChip label="Token" value={selectedEndpoint.tokenHintCount || 0} color="sky" />
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <InfoBlock title="请求键" values={selectedEndpoint.requestKeys} empty="无已提取参数键" />
            <InfoBlock title="响应信号" values={selectedEndpoint.responseIndicators} empty="无明显响应信号" />
            <InfoBlock
              title="状态码分布"
              values={(selectedEndpoint.statusCodes ?? []).map((item) => `${item.label} × ${item.count}`)}
              empty="无状态码"
            />
            <InfoBlock title="端点说明" values={selectedEndpoint.notes} empty="暂无说明" />
          </div>
        </div>
      )}
    </div>
  );
}

function HTTPLoginAttemptTable({ attempts }: { attempts: HTTPLoginAttempt[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/80 px-4 py-3">
        <div>
          <div className="text-sm font-semibold text-slate-800">认证尝试明细</div>
          <div className="mt-0.5 text-[11px] text-slate-500">按包号串联请求、响应、凭据线索与判定原因。</div>
        </div>
        <span className="shrink-0 rounded-full border border-cyan-200 bg-cyan-50 px-2.5 py-1 text-[11px] font-semibold text-cyan-700">
          {attempts.length} 条
        </span>
      </div>
      <DataTable
        data={attempts}
        rowKey={(item) => `${item.packetId}-${item.responsePacketId || 0}`}
        maxHeightClassName="max-h-[460px]"
        tableClassName="min-w-[1040px] border-separate border-spacing-0"
        wrapperClassName="rounded-none border-0 bg-white"
        headerClassName="z-10 bg-slate-100/95 text-[11px] uppercase tracking-[0.12em] shadow-[0_1px_0_0_rgba(148,163,184,0.35)] backdrop-blur"
        headerCellClassName="py-3 font-semibold"
        emptyText="暂无认证尝试"
        rowClassName="odd:bg-white even:bg-slate-50/45 hover:bg-cyan-50/45"
        cellClassName="py-3"
        columns={[
          {
            key: "request",
            header: "请求包",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] font-semibold text-slate-800",
            render: (item) => `#${item.packetId}`,
          },
          {
            key: "response",
            header: "响应包",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-600",
            render: (item) => (item.responsePacketId ? `#${item.responsePacketId}` : "--"),
          },
          {
            key: "result",
            header: "结果",
            widthClassName: "w-[104px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap",
            render: (item) => (
              <span className={attemptBadge(item.result, item.possibleBruteforce)}>
                {renderAttemptLabel(item.result, item.possibleBruteforce)}
              </span>
            ),
          },
          {
            key: "status",
            header: "状态码",
            widthClassName: "w-[84px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "whitespace-nowrap font-mono text-[12px] text-slate-700",
            render: (item) => item.statusCode || "--",
          },
          {
            key: "username",
            header: "用户名",
            widthClassName: "w-[140px]",
            headerClassName: "whitespace-nowrap",
            render: (item) => (
              <div
                className="max-w-[128px] truncate font-mono text-[11px] text-slate-700"
                title={item.username || "--"}
              >
                {item.username || "--"}
              </div>
            ),
          },
          {
            key: "keys",
            header: "参数键",
            widthClassName: "w-[170px]",
            headerClassName: "whitespace-nowrap",
            render: (item) => {
              const keys = (item.requestKeys ?? []).join(", ") || "--";
              return (
                <div className="max-w-[158px] truncate font-mono text-[11px] text-slate-600" title={keys}>
                  {keys}
                </div>
              );
            },
          },
          {
            key: "reason",
            header: "原因",
            widthClassName: "w-[190px]",
            headerClassName: "whitespace-nowrap",
            cellClassName: "text-[12px] leading-relaxed text-slate-700",
            render: (item) => item.reason || "--",
          },
          {
            key: "preview",
            header: "请求 / 响应预览",
            headerClassName: "min-w-[300px] whitespace-nowrap",
            render: (item) => (
              <div className="space-y-1.5">
                <PreviewLine label="REQ" value={item.requestPreview || "--"} tone="sky" />
                {item.responsePreview ? <PreviewLine label="RESP" value={item.responsePreview} tone="slate" /> : null}
              </div>
            ),
          },
        ]}
      />
    </div>
  );
}

function HTTPLoginBruteforceAlert({ bruteforceCount }: { bruteforceCount: number }) {
  return (
    <div className="rounded-xl border border-rose-200 bg-rose-50/80 p-4 text-sm text-rose-800 shadow-sm">
      <div className="flex items-center gap-2 font-semibold">
        <AlertTriangle className="h-4 w-4" />
        发现疑似爆破 / 批量验证
      </div>
      <div className="mt-2 text-[13px] leading-relaxed">
        当前结果中共有 {bruteforceCount} 个认证端点命中爆破特征，建议优先回到 HTTP
        流追踪页复核失败序列、用户名变化和限速/验证码响应。
      </div>
    </div>
  );
}

function HTTPLoginSuccessHint() {
  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm text-emerald-800 shadow-sm">
      <div className="flex items-center gap-2 font-semibold">
        <ShieldCheck className="h-4 w-4" />
        已识别成功认证信号
      </div>
      <div className="mt-2 text-[13px] leading-relaxed">
        成功线索通常来自 2xx/3xx + Set-Cookie、token 返回或跳转到非登录页面。你可以结合包号和 stream
        继续向下追踪后续会话行为。
      </div>
    </div>
  );
}

function InfoBlock({ title, values, empty }: { title: string; values?: string[]; empty: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</div>
      {(values?.length ?? 0) > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values!.map((value) => (
            <span
              key={value}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] text-slate-700"
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

function PreviewLine({ label, value, tone }: { label: string; value: string; tone: "sky" | "slate" }) {
  return (
    <div
      className={`flex min-w-0 items-start gap-2 rounded-lg border px-2.5 py-2 ${
        tone === "sky" ? "border-sky-100 bg-sky-50/70 text-sky-900" : "border-slate-100 bg-slate-50 text-slate-700"
      }`}
    >
      <span
        className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-[0.12em] ${
          tone === "sky" ? "bg-sky-100 text-sky-700" : "bg-slate-200/70 text-slate-600"
        }`}
      >
        {label}
      </span>
      <span className="min-w-0 break-all font-mono text-[11px] leading-relaxed">{value}</span>
    </div>
  );
}

function attemptBadge(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "rounded border border-rose-200 bg-rose-50 px-2 py-0.5 text-rose-700";
  switch (result) {
    case "success":
      return "rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-emerald-700";
    case "failure":
      return "rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-amber-700";
    default:
      return "rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-slate-700";
  }
}

function renderAttemptLabel(result?: string, bruteforce?: boolean) {
  if (bruteforce) return "疑似爆破";
  switch (result) {
    case "success":
      return "成功";
    case "failure":
      return "失败";
    default:
      return "待确认";
  }
}
