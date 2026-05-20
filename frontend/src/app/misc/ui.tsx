import type React from "react";
import { Download, ShieldAlert } from "lucide-react";
import { Button } from "../components/ui/button";
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
