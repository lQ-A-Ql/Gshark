import { cn } from "../../components/ui/utils";
import { trafficSectionGroups } from "./trafficGraphPanelModel";
import type { TrafficGraphSection } from "./trafficGraphPanelTypes";

export function TrafficGraphSectionNav({
  selectedSection,
  onSelectSection,
}: {
  selectedSection: TrafficGraphSection;
  onSelectSection: (section: TrafficGraphSection) => void;
}) {
  return (
    <nav className="flex w-56 shrink-0 flex-col overflow-y-auto border-r border-[var(--meow-tile-divider)]">
      <div className="flex flex-col gap-1 p-3">
        {trafficSectionGroups.map((group) => (
          <div key={group.label} className="mb-1">
            <div className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">{group.label}</div>
            {group.items.map((item) => (
              <SectionButton key={item.id} item={item} active={item.id === selectedSection} onSelect={onSelectSection} />
            ))}
          </div>
        ))}
      </div>
    </nav>
  );
}

function SectionButton({
  item,
  active,
  onSelect,
}: {
  item: { id: TrafficGraphSection; title: string; description: string };
  active: boolean;
  onSelect: (section: TrafficGraphSection) => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={() => onSelect(item.id)}
      className={cn(
        "flex w-full flex-col gap-0.5 rounded-sm px-2 py-2 text-left transition-all",
        active ? "bg-cyan-50/30 text-cyan-900 shadow-[inset_0_0_0_1px_rgba(6,182,212,0.18)]" : "text-slate-600 hover:bg-slate-50/40 hover:text-slate-800",
      )}
    >
      <span className="text-[13px] font-semibold">{item.title}</span>
      <span className="text-[11px] text-slate-400">{item.description}</span>
    </button>
  );
}
