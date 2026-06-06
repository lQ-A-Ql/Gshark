import { Download } from "lucide-react";

export function EvidenceExportButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="meow-control flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-foreground transition-colors"
    >
      <Download className="h-3 w-3" /> {label}
    </button>
  );
}
