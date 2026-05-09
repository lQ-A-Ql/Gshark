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
      className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition-colors ${active ? "border-blue-500 bg-blue-50 text-blue-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
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
      className={`rounded-full border px-3 py-1.5 text-xs transition-colors ${active ? "border-cyan-500 bg-cyan-50 text-cyan-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
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
        <span className="rounded border border-dashed border-border px-3 py-1.5 text-xs text-muted-foreground">
          {emptyLabel}
        </span>
      ) : (
        devices.map((device) => (
          <button
            key={device}
            type="button"
            onClick={() => onSelect(device)}
            className={`rounded-full border px-3 py-1.5 text-xs transition-colors ${activeDevice === device ? "border-blue-500 bg-blue-50 text-blue-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
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
        <div
          key={`${note}-${index}`}
          className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2"
        >
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
      {children}
    </div>
  );
}

export function Banner({ children, tone }: { children: ReactNode; tone: "muted" | "warning" }) {
  const className =
    tone === "warning"
      ? "mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700"
      : "mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground";
  return <div className={className}>{children}</div>;
}
