import type { ReactNode } from "react";
import type { EvidenceMetadataValue, UnifiedEvidenceRecord } from "../../core/evidenceTypes";

export function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="meow-soft-fill space-y-2 px-3 py-3">{children}</div>
    </section>
  );
}

export function FieldGrid({ fields }: { fields: Array<[string, string | undefined]> }) {
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {fields.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{label}</div>
          <div className="break-words text-xs leading-5 text-slate-700">{value && value.trim() ? value : "--"}</div>
        </div>
      ))}
    </div>
  );
}

export function MetadataBlock({ metadata }: { metadata?: UnifiedEvidenceRecord["metadata"] }) {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) {
    return <div className="text-xs text-slate-500">元数据未提供。</div>;
  }

  return (
    <div className="grid gap-2 md:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{key}</div>
          <div className="break-words text-xs leading-5 text-slate-700">{formatMetadataValue(value)}</div>
        </div>
      ))}
    </div>
  );
}

function formatMetadataValue(value: EvidenceMetadataValue) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : "--";
  }
  if (value == null || value === "") return "--";
  return String(value);
}
