import type { ReactNode } from "react";
import { ArrowLeft } from "lucide-react";
import { cn } from "./ui/utils";

type Tone = "slate" | "blue" | "cyan" | "emerald" | "amber" | "rose" | "indigo" | "violet";
type SurfaceVariant = "page" | "section" | "flat" | "subtle";

const toneClasses: Record<Tone, { hint: string; text: string }> = {
  slate: { hint: "border-slate-200/24 text-slate-600", text: "text-slate-700" },
  blue: { hint: "border-blue-100/28 text-blue-700", text: "text-blue-700" },
  cyan: { hint: "border-cyan-100/28 text-cyan-700", text: "text-cyan-700" },
  emerald: { hint: "border-emerald-100/28 text-emerald-700", text: "text-emerald-700" },
  amber: { hint: "border-amber-100/28 text-amber-700", text: "text-amber-700" },
  rose: { hint: "border-rose-100/28 text-rose-700", text: "text-rose-700" },
  indigo: { hint: "border-indigo-100/28 text-indigo-700", text: "text-indigo-700" },
  violet: { hint: "border-violet-100/28 text-violet-700", text: "text-violet-700" },
};

const surfaceClasses: Record<SurfaceVariant, string> = {
  page: "gshark-tile gshark-tile-strong",
  section: "gshark-tile",
  flat: "gshark-tile",
  subtle: "gshark-tile",
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
        <div className={cn("gshark-tile-header px-3.5 py-2.5", headerClassName)}>
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
      <div className={cn(variant === "flat" ? "p-3" : "p-3.5", bodyClassName)}>{children}</div>
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
    <div className={cn("gshark-tile gshark-diffuse-edge flex items-center gap-3 px-3 py-2.5", className)}>
      {icon ? <span className="shrink-0">{icon}</span> : null}
      <div className="min-w-0">
        <div className="text-[11px] leading-5 text-slate-500">{label}</div>
        <div className={cn("truncate text-sm font-semibold", toneClasses[tone].text)}>{value}</div>
        {hint ? <div className="text-[10px] leading-4 text-slate-400">{hint}</div> : null}
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
    <div className={cn("gshark-soft-fill px-3 py-2 text-xs leading-5", toneClasses[tone].hint, className)}>
      {children}
    </div>
  );
}

export function EmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("px-4 py-5 text-center text-xs leading-6 text-slate-500", className)}>
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
    <div className={cn("gshark-tile-toolbar flex shrink-0 flex-wrap items-center justify-between gap-3 border-x-0 border-t-0 px-3.5 py-2 text-foreground", className)}>
      <div className="flex min-w-0 items-center gap-3">
        {onBack ? (
          <button onClick={onBack} className="gshark-diffuse-chip p-1.5 text-muted-foreground transition-colors hover:bg-accent/55 hover:text-foreground" title="返回">
            <ArrowLeft className="h-4 w-4" />
          </button>
        ) : null}
        {onBack ? <div className="h-5 w-px bg-[var(--gshark-tile-divider)]" /> : null}
        {icon ? <div className="gshark-diffuse-chip flex h-8 w-8 shrink-0 items-center justify-center text-slate-600">{icon}</div> : null}
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
    <span className={cn("gshark-diffuse-chip inline-flex min-h-7 items-center px-2 py-1 text-[11px] leading-4 text-muted-foreground", className)}>
      {children}
    </span>
  );
}
