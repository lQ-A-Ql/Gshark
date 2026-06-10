import { useMemo } from "react";
import { cn } from "../ui/utils";
import type { AnalysisWorkbenchSection, AnalysisWorkbenchShellProps } from "./analysisWorkbenchTypes";

type SectionGroup = {
  label: string;
  items: AnalysisWorkbenchSection[];
};

export function AnalysisWorkbenchShell<TSectionId extends string>({
  sections,
  selectedSection,
  onSectionChange,
  title,
  description,
  activeSectionIds,
  children,
  className,
  contentClassName,
  navLabel = "分析工作台导航",
}: AnalysisWorkbenchShellProps<TSectionId>) {
  const groups = useMemo(() => groupSections(sections), [sections]);
  const activeIds = useMemo(() => new Set(activeSectionIds ?? [selectedSection]), [activeSectionIds, selectedSection]);
  const selectedMeta = sections.find((section) => section.id === selectedSection);
  const headerTitle = title ?? selectedMeta?.title ?? "";
  const headerDescription = description ?? selectedMeta?.description;

  return (
    <div
      className={cn(
        "meow-aurora-surface flex min-h-0 flex-1 overflow-hidden border border-[var(--meow-tile-divider)]",
        className,
      )}
    >
      <nav
        aria-label={navLabel}
        className="flex w-56 shrink-0 flex-col overflow-y-auto border-r border-[var(--meow-tile-divider)]"
      >
        <div className="flex flex-col gap-1 p-3">
          {groups.map((group) => (
            <div key={group.label} className="mb-1">
              <div className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                {group.label}
              </div>
              {group.items.map((item) => (
                <AnalysisWorkbenchNavButton
                  key={item.id}
                  item={item}
                  active={activeIds.has(item.id)}
                  onSelect={(section) => onSectionChange(section as TSectionId)}
                />
              ))}
            </div>
          ))}
        </div>
      </nav>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {(headerTitle || headerDescription) && (
          <div className="border-b border-[var(--meow-tile-divider)] px-4 py-3">
            {headerTitle && <div className="text-sm font-semibold text-slate-900">{headerTitle}</div>}
            {headerDescription && <div className="mt-1 text-xs leading-5 text-slate-500">{headerDescription}</div>}
          </div>
        )}
        <div
          data-testid="analysis-workbench-scroll"
          className={cn("min-h-0 flex-1 overflow-auto p-3", contentClassName)}
        >
          {children}
        </div>
      </div>
    </div>
  );
}

function AnalysisWorkbenchNavButton({
  item,
  active,
  onSelect,
}: {
  item: AnalysisWorkbenchSection;
  active: boolean;
  onSelect: (section: string) => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      aria-expanded={item.expanded}
      data-testid={item.testId}
      disabled={item.disabled}
      onClick={() => {
        if (!item.disabled) onSelect(item.id);
      }}
      className={cn(
        "flex w-full flex-col gap-0.5 rounded-sm px-2 py-2 text-left transition-all",
        active
          ? "bg-cyan-50/30 text-cyan-900 shadow-[inset_0_0_0_1px_rgba(6,182,212,0.18)]"
          : "text-slate-600 hover:bg-slate-50/40 hover:text-slate-800",
        item.disabled && "cursor-not-allowed opacity-50 hover:bg-transparent hover:text-slate-600",
      )}
    >
      <span className="flex min-w-0 items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2">
          {item.icon && <span className="shrink-0">{item.icon}</span>}
          <span className="truncate text-[13px] font-semibold">{item.title}</span>
        </span>
        {item.badge !== undefined && (
          <span className="shrink-0 rounded-full border border-slate-200 bg-white/70 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500">
            {item.badge}
          </span>
        )}
      </span>
      {item.description && (
        <span className="line-clamp-2 text-[11px] leading-4 text-slate-400">{item.description}</span>
      )}
    </button>
  );
}

function groupSections(sections: readonly AnalysisWorkbenchSection[]): SectionGroup[] {
  const groups: SectionGroup[] = [];
  for (const section of sections) {
    const label = section.group ?? "Sections";
    let group = groups.find((item) => item.label === label);
    if (!group) {
      group = { label, items: [] };
      groups.push(group);
    }
    group.items.push(section);
  }
  return groups.filter((group) => group.items.length > 0);
}
