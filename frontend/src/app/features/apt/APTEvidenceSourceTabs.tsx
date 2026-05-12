import { cn } from "../../components/ui/utils";

export type EvidenceSourceTab = "all" | "c2" | "delivery" | "hunting" | "credential";

export function EvidenceSourceTabs({
  tabs,
  active,
  onChange,
}: {
  tabs: Array<{ id: EvidenceSourceTab; label: string; count: number }>;
  active: EvidenceSourceTab;
  onChange: (tab: EvidenceSourceTab) => void;
}) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={cn(
            "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition",
            active === tab.id
              ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm"
              : "border-slate-200 bg-white text-slate-600 hover:border-indigo-100 hover:bg-indigo-50/50",
          )}
        >
          <span>{tab.label}</span>
          <span className="rounded-full bg-white/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
            {tab.count}
          </span>
        </button>
      ))}
    </div>
  );
}
