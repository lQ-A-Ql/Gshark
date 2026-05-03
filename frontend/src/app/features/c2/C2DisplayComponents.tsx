import { Activity, Network, Workflow } from "lucide-react";
import type { ReactNode } from "react";
import { EmptyState, SurfacePanel } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { VShellEvidenceSummaryItem } from "./c2EvidenceModel";

export function C2Panel({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <SurfacePanel title={title} icon={<Network className="h-4 w-4 text-rose-600" />} className={className}>
      {children}
    </SurfacePanel>
  );
}

export function C2FamilyTabButton({ active, onClick, icon, title, description }: { active: boolean; onClick: () => void; icon: ReactNode; title: string; description: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 rounded-[22px] border px-4 py-4 text-left transition-all",
        active
          ? "border-rose-200 bg-rose-50/90 text-rose-700 shadow-[0_18px_46px_-30px_rgba(225,29,72,0.55)]"
          : "border-transparent bg-transparent text-slate-500 hover:border-slate-200 hover:bg-white",
      )}
    >
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-current/20 bg-white/70">{icon}</span>
      <span>
        <span className="block text-sm font-semibold">{title}</span>
        <span className="mt-1 block text-xs leading-5 opacity-75">{description}</span>
      </span>
    </button>
  );
}

export function C2FeatureCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-[24px] border border-rose-100 bg-[linear-gradient(135deg,rgba(255,241,242,0.86),rgba(255,255,255,0.96))] px-4 py-4">
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
    <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-7">
      {items.map((item) => (
        <div key={item.label} className="rounded-[22px] border border-cyan-100 bg-[linear-gradient(135deg,rgba(236,254,255,0.82),rgba(255,255,255,0.96))] px-4 py-3 shadow-[0_18px_48px_-40px_rgba(8,145,178,0.45)]">
          <div className="flex items-center justify-between gap-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-600">{item.label}</div>
            {item.source ? (
              <span className="rounded-full border border-cyan-200 bg-white/80 px-2 py-0.5 text-[10px] font-semibold text-cyan-700">
                {item.source}
              </span>
            ) : null}
          </div>
          <div className="mt-1 font-mono text-2xl font-semibold text-slate-950">{item.value}</div>
          <div className="mt-1 text-[11px] leading-5 text-slate-500">{item.helper}</div>
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
        <div key={`${note}-${index}`} className="flex items-start gap-2 rounded-2xl border border-slate-100 bg-slate-50/70 px-3 py-2 text-xs leading-5 text-slate-600">
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}
