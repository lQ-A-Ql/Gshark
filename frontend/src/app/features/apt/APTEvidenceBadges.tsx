export function TagLine({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-[11px] text-slate-400">--</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="gshark-diffuse-chip px-2 py-0.5 text-[11px] font-medium text-slate-600">
          {value}
        </span>
      ))}
    </div>
  );
}

export function CaveatLine({ values }: { values: string[] }) {
  return (
    <div className="space-y-1">
      {values.slice(0, 2).map((value) => (
        <div
          key={value}
          className="gshark-diffuse-chip border-amber-100/30 bg-amber-50/16 px-2 py-1 text-[10px] leading-4 text-amber-700"
        >
          {value}
        </div>
      ))}
    </div>
  );
}
