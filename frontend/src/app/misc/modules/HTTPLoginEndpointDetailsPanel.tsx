import type { HTTPLoginEndpoint } from "../../core/types";
import { MetaChip } from "../ui";

interface HTTPLoginEndpointDetailsPanelProps {
  selectedEndpoint: HTTPLoginEndpoint | null;
}

export function HTTPLoginEndpointDetailsPanel({ selectedEndpoint }: HTTPLoginEndpointDetailsPanelProps) {
  return (
    <div className="gshark-tile border-slate-200 p-4">
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

function InfoBlock({ title, values, empty }: { title: string; values?: string[]; empty: string }) {
  return (
    <div className="gshark-tile border-slate-200 bg-slate-50/70 p-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</div>
      {(values?.length ?? 0) > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values!.map((value) => (
            <span
              key={value}
              className="rounded-sm border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-700"
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
