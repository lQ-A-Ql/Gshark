import type React from "react";
import { Download, ShieldAlert } from "lucide-react";
import { Button } from "../components/ui/button";
import type { MiscExportFormat } from "./exportResult";

export function Field({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
  return (
    <label className={`group/field flex min-w-0 flex-col gap-2 text-[13px] ${className ?? ""}`}>
      <span className="flex items-center gap-2 font-semibold text-slate-700">
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-[0_0_0_3px_rgba(34,211,238,0.14)] transition-colors group-focus-within/field:bg-sky-500" />
        {label}
      </span>
      {children}
    </label>
  );
}

export function ErrorBlock({ message }: { message: string }) {
  return (
    <div className="mt-2 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-50 px-4 py-3 text-[13px] text-rose-700 shadow-sm">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
      <div className="break-all font-medium leading-relaxed">{message}</div>
    </div>
  );
}

export function NotesList({
  notes,
  className = "space-y-2",
  itemClassName = "rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600",
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
      <Button type="button" variant="outline" onClick={() => onExport("json")} disabled={disabled} className="gap-2 bg-white text-slate-700">
        <Download className="h-4 w-4 text-blue-600" />
        导出 JSON
      </Button>
      <Button type="button" variant="outline" onClick={() => onExport("txt")} disabled={disabled} className="gap-2 bg-white text-slate-700">
        <Download className="h-4 w-4 text-emerald-600" />
        导出 TXT
      </Button>
    </>
  );
}

export function MetaChip({ label, value, color = "slate" }: { label: string; value: React.ReactNode; color?: "slate" | "rose" | "sky" | "emerald" }) {
  const colorStyles = {
    slate: "border-slate-200 bg-white text-slate-700",
    rose: "border-rose-200 bg-white font-semibold text-rose-700",
    sky: "border-sky-200 bg-white font-semibold text-sky-700",
    emerald: "border-emerald-200 bg-white font-semibold text-emerald-700",
  };
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-1 text-xs shadow-sm ${colorStyles[color]}`}>
      <span className="mr-1.5 text-slate-500">{label}</span>
      {value}
    </span>
  );
}
