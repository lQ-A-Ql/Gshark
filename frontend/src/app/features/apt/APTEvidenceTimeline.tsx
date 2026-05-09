import type { APTEvidenceRecord } from "../../core/types";

export function EvidenceTimeline({ evidence }: { evidence: APTEvidenceRecord[] }) {
  const sorted = [...evidence]
    .sort((a, b) => {
      const aHasTime = Boolean(a.time);
      const bHasTime = Boolean(b.time);
      if (aHasTime !== bHasTime) return aHasTime ? -1 : 1;
      return String(a.time ?? "").localeCompare(String(b.time ?? ""));
    })
    .slice(0, 50);

  return (
    <div className="mt-4 rounded-2xl border border-slate-100 bg-white/90 px-4 py-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Evidence Timeline</div>
          <div className="mt-1 text-xs text-slate-500">
            按当前 actor 与证据来源 tab 排序展示前 50 条；无时间证据置于末尾。
          </div>
        </div>
        <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[10px] text-slate-500">
          {sorted.length}/{evidence.length}
        </span>
      </div>
      {sorted.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-4 text-center text-xs text-slate-500">
          暂无可用于时间线的证据。
        </div>
      ) : (
        <div className="space-y-2">
          {sorted.map((item, index) => (
            <div
              key={`${item.packetId}-${item.sourceModule}-${index}`}
              className="grid gap-3 rounded-xl border border-slate-100 bg-slate-50/60 px-3 py-2 text-xs md:grid-cols-[8rem_minmax(0,1fr)]"
            >
              <div className="font-mono text-[11px] text-slate-500">{item.time || "no-time"}</div>
              <div>
                <div className="font-semibold text-slate-800">
                  {item.sourceModule || "unknown"} · {item.evidenceType || "evidence"} · confidence{" "}
                  {item.confidence ?? 0}
                </div>
                <div className="mt-1 leading-5 text-slate-600">{item.summary || item.evidenceValue || "--"}</div>
                <div className="mt-2">
                  <TagLine
                    values={[...(item.tags ?? []), item.sampleFamily ?? "", item.campaignStage ?? ""].filter(Boolean)}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TagLine({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-[11px] text-slate-400">--</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span
          key={value}
          className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600"
        >
          {value}
        </span>
      ))}
    </div>
  );
}
