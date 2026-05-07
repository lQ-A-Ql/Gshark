import type { ReactNode } from "react";
import { ArrowLeft } from "lucide-react";
import { cn } from "./ui/utils";

type Tone = "slate" | "blue" | "cyan" | "emerald" | "amber" | "rose" | "indigo" | "violet";
type SurfaceVariant = "page" | "section" | "flat" | "subtle";

const toneClasses: Record<Tone, { icon: string; hint: string }> = {
  slate: { icon: "border-slate-200 bg-slate-50 text-slate-600", hint: "border-slate-200 bg-slate-50 text-slate-600" },
  blue: { icon: "border-blue-100 bg-blue-50 text-blue-600", hint: "border-blue-100 bg-blue-50 text-blue-700" },
  cyan: { icon: "border-cyan-100 bg-cyan-50 text-cyan-600", hint: "border-cyan-100 bg-cyan-50 text-cyan-700" },
  emerald: { icon: "border-emerald-100 bg-emerald-50 text-emerald-600", hint: "border-emerald-100 bg-emerald-50 text-emerald-700" },
  amber: { icon: "border-amber-100 bg-amber-50 text-amber-600", hint: "border-amber-100 bg-amber-50 text-amber-700" },
  rose: { icon: "border-rose-100 bg-rose-50 text-rose-600", hint: "border-rose-100 bg-rose-50 text-rose-700" },
  indigo: { icon: "border-indigo-100 bg-indigo-50 text-indigo-600", hint: "border-indigo-100 bg-indigo-50 text-indigo-700" },
  violet: { icon: "border-violet-100 bg-violet-50 text-violet-600", hint: "border-violet-100 bg-violet-50 text-violet-700" },
};

const surfaceClasses: Record<SurfaceVariant, string> = {
  page: "rounded-[28px] border border-slate-200/80 bg-white/92 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.42)]",
  section: "rounded-[24px] border border-slate-200/80 bg-white/90 shadow-[0_18px_58px_-48px_rgba(15,23,42,0.5)]",
  flat: "rounded-2xl border border-slate-100 bg-slate-50/60 shadow-none",
  subtle: "rounded-2xl border border-slate-100 bg-white/80 shadow-none",
};

export function SurfacePanel({
  title,
  description,
  icon,
  actions,
  children,
  className,
  bodyClassName,
  headerClassName,
  variant = "page",
}: {
  title?: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  headerClassName?: string;
  variant?: SurfaceVariant;
}) {
  const hasHeader = title || description || icon || actions;
  return (
    <section className={cn("min-w-0 overflow-hidden", surfaceClasses[variant], className)}>
      {hasHeader ? (
        <div className={cn("border-b border-slate-100 px-5 py-4", variant === "flat" && "bg-transparent", headerClassName)}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              {title || icon ? (
                <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-slate-900">
                  {icon ? <span className="shrink-0">{icon}</span> : null}
                  <span className="truncate">{title}</span>
                </div>
              ) : null}
              {description ? <div className="mt-1 text-xs leading-5 text-slate-500">{description}</div> : null}
            </div>
            {actions ? <div className="shrink-0">{actions}</div> : null}
          </div>
        </div>
      ) : null}
      <div className={cn(variant === "flat" ? "p-4" : "p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function MetricCard({
  label,
  value,
  hint,
  icon,
  tone = "slate",
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-3 rounded-2xl border px-4 py-3", toneClasses[tone].icon, className)}>
      {icon ? <span className="shrink-0">{icon}</span> : null}
      <div className="min-w-0">
        <div className="text-[11px] leading-5 opacity-70">{label}</div>
        <div className="truncate text-sm font-semibold">{value}</div>
        {hint ? <div className="text-[10px] leading-4 opacity-60">{hint}</div> : null}
      </div>
    </div>
  );
}

export function StatusHint({
  children,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <div className={cn("rounded-2xl border px-4 py-3 text-xs leading-5", toneClasses[tone].hint, className)}>
      {children}
    </div>
  );
}

export function EmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-center text-xs leading-6 text-slate-500", className)}>
      {children}
    </div>
  );
}

export function CollapsibleContent({
  open,
  children,
  className,
}: {
  open: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      aria-hidden={!open}
      className={cn(
        "grid transition-[grid-template-rows,opacity,visibility] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]",
        open ? "visible grid-rows-[1fr] opacity-100" : "pointer-events-none invisible grid-rows-[0fr] opacity-0",
        className,
      )}
    >
      <div className="min-h-0 overflow-hidden">{children}</div>
    </div>
  );
}

export function WorkbenchTitleBar({
  title,
  subtitle,
  icon,
  onBack,
  meta,
  actions,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  onBack?: () => void;
  meta?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border bg-white px-4 py-2.5 text-foreground shadow-sm", className)}>
      <div className="flex min-w-0 items-center gap-3">
        {onBack ? (
          <button onClick={onBack} className="rounded-md border border-border bg-background p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground" title="返回">
            <ArrowLeft className="h-4 w-4" />
          </button>
        ) : null}
        {onBack ? <div className="h-5 w-px bg-border" /> : null}
        {icon ? <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-600">{icon}</div> : null}
        <div className="min-w-0">
          <h1 className="truncate text-sm font-semibold text-foreground">{title}</h1>
          {subtitle ? <div className="mt-0.5 min-w-0 text-[11px] leading-4 text-muted-foreground">{subtitle}</div> : null}
        </div>
      </div>
      <div className="flex min-w-0 flex-1 flex-wrap items-center justify-end gap-2">
        {meta}
        {actions}
      </div>
    </div>
  );
}

export function WorkbenchChip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex min-h-7 items-center rounded-md border border-border bg-background px-2 py-1 text-[11px] leading-4 text-muted-foreground", className)}>
      {children}
    </span>
  );
}
