import { Activity, Network, Workflow } from "lucide-react";
import type { ReactNode } from "react";
import { EmptyState, SurfacePanel } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { VShellEvidenceSummaryItem } from "./c2EvidenceModel";

export function C2Panel({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <SurfacePanel
      title={title}
      icon={<Network className="h-4 w-4 text-rose-600" />}
      className={cn("gshark-tile", className)}
    >
      {children}
    </SurfacePanel>
  );
}

export function C2FamilyTabButton({
  active,
  onClick,
  icon,
  title,
  description,
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "gshark-tile flex items-center gap-3 px-3.5 py-3 text-left transition-all",
        active
          ? "border-rose-200 bg-rose-50/90 text-rose-700"
          : "border-transparent bg-transparent text-slate-500 hover:border-rose-200/30 hover:bg-rose-50/20 hover:text-rose-700",
      )}
    >
      <span className="gshark-diffuse-chip flex h-9 w-9 shrink-0 items-center justify-center text-current">{icon}</span>
      <span>
        <span className="block text-sm font-semibold">{title}</span>
        <span className="mt-1 block text-xs leading-5 opacity-75">{description}</span>
      </span>
    </button>
  );
}

export function C2FeatureCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="gshark-tile border-rose-100 px-3.5 py-3">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <Activity className="h-4 w-4 text-rose-600" />
        {title}
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-600">{text}</p>
    </div>
  );
}

export function VShellEvidenceSummaryGrid({ items }: { items: VShellEvidenceSummaryItem[] }) {
  return (
    <div className="gshark-tile-grid mt-0 grid grid-cols-1 gap-0 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-7">
      {items.map((item) => (
        <div key={item.label} className="gshark-tile border-cyan-100 px-3.5 py-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-600">{item.label}</div>
            {item.source ? (
              <span className="rounded-full border border-cyan-200 bg-cyan-50 px-2 py-0.5 text-[10px] font-semibold text-cyan-700">
                {item.source}
              </span>
            ) : null}
          </div>
          <div className="mt-1 font-mono text-xl font-semibold text-slate-950">{item.value}</div>
          <div className="mt-1 text-[11px] leading-5 text-slate-500">{item.helper}</div>
        </div>
      ))}
    </div>
  );
}

export function C2AptHandoffNotes({ notes }: { notes: string[] }) {
  return (
    <div className="space-y-2">
      {notes.map((note, index) => (
        <div
          key={`${note}-${index}`}
          className="gshark-tile flex items-start gap-2 border-amber-100 bg-amber-50/70 px-3 py-2 text-xs leading-5 text-amber-800"
        >
          <Workflow className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

export function C2NotesPanel({ notes, emptyText }: { notes: string[]; emptyText: string }) {
  if (notes.length === 0) {
    return <EmptyState className="text-left">{emptyText}</EmptyState>;
  }
  return (
    <div className="space-y-2">
      {notes.map((note, index) => (
        <div
          key={`${note}-${index}`}
          className="gshark-soft-fill flex items-start gap-2 px-3 py-2 text-xs leading-5 text-slate-600"
        >
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}
