import type React from "react";
import { Download, ShieldAlert } from "lucide-react";
import { Button } from "../components/ui/button";
import { cn } from "../components/ui/utils";
import type { MiscExportFormat } from "./exportResult";

export function Field({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <label className={`group/field flex min-w-0 flex-col gap-2 text-[13px] ${className ?? ""}`}>
      <span className="flex items-center gap-2 font-semibold text-slate-700">
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 transition-colors group-focus-within/field:bg-sky-500" />
        {label}
      </span>
      {children}
    </label>
  );
}

export function ErrorBlock({ message }: { message: string }) {
  return (
    <div className="gshark-soft-fill gshark-risk-accent mt-2 flex items-start gap-2 px-4 py-3 text-[13px] text-rose-700">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
      <div className="break-all font-medium leading-relaxed">{message}</div>
    </div>
  );
}

type SurfaceTone = "slate" | "sky" | "cyan" | "emerald" | "amber" | "rose" | "violet" | "indigo";

const surfaceNoteToneClasses: Record<SurfaceTone, string> = {
  slate: "text-slate-600",
  sky: "gshark-evidence-accent text-sky-900",
  cyan: "gshark-evidence-accent text-cyan-900",
  emerald: "gshark-evidence-accent text-emerald-900",
  amber: "gshark-risk-accent text-amber-800",
  rose: "gshark-risk-accent text-rose-700",
  violet: "gshark-evidence-accent text-violet-900",
  indigo: "gshark-evidence-accent text-indigo-900",
};

export function EmptyState({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("gshark-soft-fill border-dashed px-3 py-8 text-center text-[13px] text-slate-500", className)}>
      {children}
    </div>
  );
}

export function SurfaceNote({
  children,
  className,
  tone = "slate",
}: {
  children: React.ReactNode;
  className?: string;
  tone?: SurfaceTone;
}) {
  return (
    <div className={cn("gshark-soft-fill px-3 py-2 text-[12px] leading-5", surfaceNoteToneClasses[tone], className)}>
      {children}
    </div>
  );
}

export function SurfaceInfoBlock({
  title,
  values,
  empty,
  className,
  tone = "slate",
}: {
  title: string;
  values?: string[];
  empty: string;
  className?: string;
  tone?: Exclude<SurfaceTone, "cyan">;
}) {
  const toneClass =
    tone === "rose"
      ? "gshark-soft-fill gshark-risk-accent"
      : tone === "amber"
        ? "gshark-soft-fill gshark-risk-accent"
        : tone === "sky"
          ? "gshark-soft-fill gshark-evidence-accent"
          : tone === "emerald"
            ? "gshark-soft-fill gshark-evidence-accent"
            : tone === "violet"
              ? "gshark-soft-fill gshark-evidence-accent"
              : tone === "indigo"
                ? "gshark-soft-fill gshark-evidence-accent"
                : "gshark-soft-fill";

  return (
    <div className={cn(toneClass, "p-3", className)}>
      <div className="mb-2 text-[12px] font-semibold text-slate-700">{title}</div>
      {values && values.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {values.map((value) => (
            <span
              key={`${title}-${value}`}
              className="gshark-diffuse-chip px-2 py-1 font-mono text-[11px] text-slate-700"
            >
              {value}
            </span>
          ))}
        </div>
      ) : (
        <div className="text-[12px] text-slate-500">{empty}</div>
      )}
    </div>
  );
}

export function ContrastPreview({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        "overflow-auto border border-slate-900/35 bg-slate-950/88 p-3.5 font-mono text-xs leading-relaxed text-cyan-50 selection:bg-cyan-100 selection:text-slate-950",
        className,
      )}
    >
      {children}
    </pre>
  );
}

export function NotesList({
  notes,
  className = "space-y-2",
  itemClassName = "gshark-soft-fill px-3 py-2 text-[12px] text-slate-600",
}: {
  notes?: string[];
  className?: string;
  itemClassName?: string;
}) {
  if (!notes?.length) {
    return null;
  }
  return (
    <div className={className}>
      {notes.map((note, index) => (
        <div key={`${index}-${note}`} className={itemClassName}>
          {note}
        </div>
      ))}
    </div>
  );
}

export function ExportButtons({
  disabled,
  onExport,
}: {
  disabled: boolean;
  onExport: (format: MiscExportFormat) => void;
}) {
  return (
    <>
      <Button
        type="button"
        variant="outline"
        onClick={() => onExport("json")}
        disabled={disabled}
        className="gap-2 text-slate-700"
      >
        <Download className="h-4 w-4 text-blue-600" />
        导出 JSON
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={() => onExport("txt")}
        disabled={disabled}
        className="gap-2 text-slate-700"
      >
        <Download className="h-4 w-4 text-emerald-600" />
        导出 TXT
      </Button>
    </>
  );
}

export function MetaChip({
  label,
  value,
  color = "slate",
}: {
  label: string;
  value: React.ReactNode;
  color?: "slate" | "rose" | "sky" | "emerald";
}) {
  const colorStyles = {
    slate: "gshark-evidence-accent text-slate-700",
    rose: "gshark-risk-accent font-semibold text-rose-700",
    sky: "gshark-evidence-accent font-semibold text-sky-700",
    emerald: "gshark-evidence-accent font-semibold text-emerald-700",
  };
  return (
    <span className={`gshark-diffuse-chip inline-flex items-center px-2 py-1 text-xs ${colorStyles[color]}`}>
      <span className="mr-1.5 text-slate-500">{label}</span>
      {value}
    </span>
  );
}
