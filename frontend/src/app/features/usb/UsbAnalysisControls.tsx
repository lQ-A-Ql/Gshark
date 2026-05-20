import { Workflow } from "lucide-react";
import type { ReactNode } from "react";

export function PrimaryTabButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`gshark-control inline-flex items-center gap-2 px-4 py-2 text-sm transition-colors ${active ? "border-blue-300/30 bg-blue-50/26 text-blue-700" : "text-muted-foreground hover:text-foreground"}`}
    >
      {icon}
      {children}
    </button>
  );
}

export function SecondaryTabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`gshark-control px-3 py-1.5 text-xs transition-colors ${active ? "border-cyan-300/30 bg-cyan-50/24 text-cyan-700" : "text-muted-foreground hover:text-foreground"}`}
    >
      {children}
    </button>
  );
}

export function DeviceChips({
  devices,
  activeDevice,
  emptyLabel,
  onSelect,
}: {
  devices: string[];
  activeDevice: string;
  emptyLabel: string;
  onSelect: (device: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {devices.length === 0 ? (
        <span className="px-3 py-1.5 text-xs text-muted-foreground">{emptyLabel}</span>
      ) : (
        devices.map((device) => (
          <button
            key={device}
            type="button"
            onClick={() => onSelect(device)}
            className={`gshark-control px-3 py-1.5 text-xs transition-colors ${activeDevice === device ? "border-blue-300/30 bg-blue-50/24 text-blue-700" : "text-muted-foreground hover:text-foreground"}`}
          >
            {device}
          </button>
        ))
      )}
    </div>
  );
}

export function NotesList({ notes, emptyLabel }: { notes: string[]; emptyLabel: string }) {
  if (notes.length === 0) {
    return <EmptyState>{emptyLabel}</EmptyState>;
  }
  return (
    <div className="space-y-2 text-sm">
      {notes.map((note, index) => (
        <div key={`${note}-${index}`} className="gshark-soft-fill flex items-start gap-2 px-3 py-2">
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="px-3 py-6 text-center text-xs leading-6 text-muted-foreground">{children}</div>;
}

export function Banner({ children, tone }: { children: ReactNode; tone: "muted" | "warning" }) {
  const className =
    tone === "warning"
      ? "gshark-tile mb-3 border-amber-300 px-3 py-2 text-xs text-amber-700"
      : "gshark-tile mb-3 border-border px-3 py-2 text-xs text-muted-foreground";
  return <div className={className}>{children}</div>;
}
