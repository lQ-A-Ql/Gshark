import type { ShiroRememberMeCandidate } from "../../core/types";
import { isShiroDeleteMeCandidate, renderShiroCandidateTitle } from "./ShiroRememberMeUtils";

interface ShiroRememberMeCandidateListProps {
  candidates: ShiroRememberMeCandidate[];
  hasCapture: boolean;
  onSelectCandidate: (packetId: number) => void;
  selectedCandidate: ShiroRememberMeCandidate | null;
}

export function ShiroRememberMeCandidateList({
  candidates,
  hasCapture,
  onSelectCandidate,
  selectedCandidate,
}: ShiroRememberMeCandidateListProps) {
  return (
    <div className="gshark-tile border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-800">rememberMe 候选</div>
        <div className="text-[11px] text-slate-500">{candidates.length} 条</div>
      </div>
      <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
        {candidates.length === 0 ? (
          <div className="gshark-tile border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            {hasCapture ? "当前筛选下没有 Shiro rememberMe 线索" : "未加载抓包"}
          </div>
        ) : (
          candidates.map((item) => {
            const selected = selectedCandidate?.packetId === item.packetId;
            return (
              <button
                key={`shiro-${item.packetId}-${item.cookieName}`}
                type="button"
                onClick={() => onSelectCandidate(item.packetId)}
                className={`w-full rounded-sm border px-3 py-3 text-left transition-colors ${
                  selected
                    ? "border-amber-300 bg-amber-50 ring-1 ring-amber-100"
                    : "border-slate-200 bg-slate-50/80 hover:border-amber-200 hover:bg-amber-50/40"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1 font-mono text-[11px] font-semibold text-amber-700">
                    #{item.packetId}
                  </span>
                  {item.hitCount ? (
                    <span className="rounded-md bg-rose-100 px-2 py-1 text-[11px] font-semibold text-rose-700">
                      Key 命中
                    </span>
                  ) : null}
                  {isShiroDeleteMeCandidate(item) ? (
                    <span className="rounded-md bg-slate-100 px-2 py-1 text-[11px] font-semibold text-slate-600">
                      deleteMe
                    </span>
                  ) : null}
                  <span className="text-[11px] text-slate-500">{item.sourceHeader || "Cookie"}</span>
                </div>
                <div className="mt-2 break-all font-medium text-slate-800">{renderShiroCandidateTitle(item)}</div>
                <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{item.cookiePreview || "--"}</div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
