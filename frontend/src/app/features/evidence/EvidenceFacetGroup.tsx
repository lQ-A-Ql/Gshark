import { cn } from "../../components/ui/utils";

export function EvidenceFacetGroup({
  title,
  options,
  selected,
  onToggle,
}: {
  title: string;
  options: { value: string; label: string; count: number }[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  if (options.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="space-y-1.5">
        {options.map((option) => {
          const active = selected.includes(option.value);
          return (
            <button
              key={`${title}-${option.value}`}
              type="button"
              onClick={() => onToggle(option.value)}
              className={cn(
                "meow-soft-fill flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-xs transition-colors",
                active ? "border-indigo-200 bg-indigo-50 text-indigo-700" : "text-slate-600 hover:text-slate-900",
              )}
            >
              <span className="min-w-0 truncate">{option.label}</span>
              <span className="shrink-0 text-[10px] text-slate-400">{option.count}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
