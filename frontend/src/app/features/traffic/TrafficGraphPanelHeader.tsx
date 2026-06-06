export function TrafficGraphPanelHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="border-b border-[var(--meow-tile-divider)] px-5 py-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">Traffic Graph</div>
      <div className="mt-1 text-lg font-semibold text-slate-900">{title}</div>
      <div className="mt-1 text-sm text-slate-500">{description}</div>
    </div>
  );
}
