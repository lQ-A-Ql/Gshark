import type { NTLMSessionMaterial } from "../../core/types";

interface NTLMSessionMaterialListProps {
  filtered: NTLMSessionMaterial[];
  hasCapture: boolean;
  onSelectFrame: (frameNumber: string) => void;
  selected: NTLMSessionMaterial | null;
}

export function NTLMSessionMaterialList({
  filtered,
  hasCapture,
  onSelectFrame,
  selected,
}: NTLMSessionMaterialListProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-800">会话材料列表</div>
        <div className="text-[11px] text-slate-500">{filtered.length} 条</div>
      </div>
      <div className="max-h-[520px] space-y-2 overflow-auto pr-1">
        {filtered.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-8 text-center text-[13px] text-slate-500">
            {hasCapture ? "当前筛选下没有匹配的 NTLM 会话材料" : "未加载抓包"}
          </div>
        ) : (
          filtered.map((item) => {
            const selectedRow = selected?.frameNumber === item.frameNumber;
            return (
              <button
                key={`${item.frameNumber}-${item.protocol}-${item.displayLabel}`}
                type="button"
                onClick={() => onSelectFrame(item.frameNumber)}
                className={`w-full rounded-xl border px-3 py-3 text-left transition-all ${
                  selectedRow
                    ? "border-violet-400 bg-violet-50 shadow-sm ring-2 ring-violet-100"
                    : "border-slate-200 bg-white hover:border-violet-200 hover:bg-violet-50/40"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-md border border-violet-200 bg-violet-50 px-2 py-1 font-mono text-[11px] font-semibold text-violet-700">
                    {item.protocol}
                  </span>
                  <span
                    className={`rounded-md px-2 py-1 text-[11px] font-semibold ${
                      item.complete ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"
                    }`}
                  >
                    {item.complete ? "材料完整" : "待补字段"}
                  </span>
                  <span className="text-[11px] text-slate-500">帧 #{item.frameNumber}</span>
                  {item.transport && <span className="text-[11px] text-slate-500">{item.transport}</span>}
                </div>
                <div className="mt-2 font-medium text-slate-800">{item.userDisplay || item.displayLabel}</div>
                <div className="mt-1 break-all font-mono text-[12px] text-slate-600">
                  {(item.src || "?") + " -> " + (item.dst || "?")}
                </div>
                {item.info && <div className="mt-1 line-clamp-2 text-[12px] text-slate-500">{item.info}</div>}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
