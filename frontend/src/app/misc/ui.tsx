import type React from "react";
import { ShieldAlert } from "lucide-react";

export function Field({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
  return (
    <label className={`flex min-w-0 flex-col gap-1.5 text-[13px] ${className ?? ""}`}>
      <span className="font-semibold text-slate-700">{label}</span>
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
