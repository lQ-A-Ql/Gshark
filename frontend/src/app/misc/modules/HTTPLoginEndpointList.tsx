import type { HTTPLoginEndpoint } from "../../core/types";
import { renderHTTPLoginEndpointTitle } from "./HTTPLoginAnalysisUtils";

interface HTTPLoginEndpointListProps {
  hasCapture: boolean;
  endpoints: HTTPLoginEndpoint[];
  selectedEndpoint: HTTPLoginEndpoint | null;
  onSelectEndpoint: (endpointKey: string) => void;
}

export function HTTPLoginEndpointList({
  hasCapture,
  endpoints,
  selectedEndpoint,
  onSelectEndpoint,
}: HTTPLoginEndpointListProps) {
  return (
    <div className="gshark-tile border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-800">认证端点</div>
        <div className="text-[11px] text-slate-500">{endpoints.length} 条</div>
      </div>
      <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
        {endpoints.length === 0 ? (
          <div className="gshark-tile border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            {hasCapture ? "未识别到符合条件的 HTTP 登录端点" : "未加载抓包"}
          </div>
        ) : (
          endpoints.map((item) => (
            <button
              key={item.key}
              type="button"
              onClick={() => onSelectEndpoint(item.key)}
              className={`w-full rounded-sm border px-3 py-3 text-left transition-colors ${
                selectedEndpoint?.key === item.key
                  ? "border-cyan-300 bg-cyan-50 ring-1 ring-cyan-100"
                  : "border-slate-200 bg-slate-50/80 hover:border-cyan-200 hover:bg-cyan-50/40"
              }`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 font-mono text-[11px] font-semibold text-cyan-700">
                  {item.method || "HTTP"}
                </span>
                {item.possibleBruteforce ? (
                  <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">
                    疑似爆破
                  </span>
                ) : null}
                <span className="text-[11px] text-slate-500">{item.attemptCount} 次尝试</span>
              </div>
              <div className="mt-2 break-all font-medium text-slate-800">{renderHTTPLoginEndpointTitle(item)}</div>
              <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                <span>成功 {item.successCount}</span>
                <span>失败 {item.failureCount}</span>
                <span>待确认 {item.uncertainCount}</span>
                {item.usernameVariants ? <span>用户变体 {item.usernameVariants}</span> : null}
              </div>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
