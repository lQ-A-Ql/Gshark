import type { C2IndicatorRecord } from "../../core/types";
import { candidatePreviewRecord } from "./C2CandidateTableRules";

export function CandidateDetailPanel({ item, tags }: { item: C2IndicatorRecord; tags: string[] }) {
  return (
    <div className="overflow-hidden rounded-[24px] border border-rose-100 bg-white/95 p-4 shadow-[0_20px_60px_-48px_rgba(15,23,42,0.55)] transition-all duration-200">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Evidence Context</div>
          <CandidateContext item={item} />
          <div className="mt-3">
            <CandidateTagLine values={tags} />
          </div>
        </div>
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">
            Typed Record Preview
          </div>
          <pre className="max-h-60 overflow-auto rounded-2xl border border-slate-100 bg-slate-950 p-3 text-[11px] leading-5 text-slate-100">
            {JSON.stringify(candidatePreviewRecord(item), null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

export function CandidateTagLine({ values }: { values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span
          key={value}
          className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold text-slate-500"
        >
          {value}
        </span>
      ))}
    </div>
  );
}

function CandidateContext({ item }: { item: C2IndicatorRecord }) {
  const endpoint = item.source || item.destination ? `${item.source || "?"} → ${item.destination || "?"}` : "";
  const rows = [
    { label: "时间", value: item.time },
    { label: "Stream", value: typeof item.streamId === "number" ? String(item.streamId) : "" },
    { label: "端点", value: endpoint },
    { label: "Host", value: item.host },
    { label: "URI", value: item.uri },
    { label: "Method", value: item.method },
    { label: "Evidence", value: item.evidence },
  ].filter((row) => row.value && String(row.value).trim() !== "");

  if (rows.length === 0) return null;

  return (
    <div className="mt-2 grid gap-1.5 rounded-2xl border border-slate-100 bg-slate-50/70 p-2">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2 text-[11px] leading-5">
          <span className="font-semibold text-slate-400">{row.label}</span>
          <span className="break-all font-mono text-slate-600">{row.value}</span>
        </div>
      ))}
    </div>
  );
}
