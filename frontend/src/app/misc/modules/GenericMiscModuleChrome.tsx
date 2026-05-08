import type { ReactNode } from "react";
import { Card, CardContent } from "../../components/ui/card";
import type { MiscModuleManifest } from "../../core/types";
import { GenericMiscModuleCapabilities, GenericMiscModuleTags } from "./GenericMiscModuleBadges";
import { GenericMiscCardHeader, GenericMiscEmbeddedHeader } from "./GenericMiscModuleHeader";

interface GenericMiscModuleChromeProps {
  module: MiscModuleManifest;
  surfaceVariant: "card" | "embedded";
  children: ReactNode;
  canDelete: boolean;
  deleting: boolean;
  running: boolean;
  onDelete: () => void;
}

export function GenericMiscModuleChrome({
  module,
  surfaceVariant,
  children,
  canDelete,
  deleting,
  running,
  onDelete,
}: GenericMiscModuleChromeProps) {
  const embedded = surfaceVariant === "embedded";
  const body = (
    <div
      className={
        embedded ? "space-y-5" : "space-y-5 rounded-b-xl bg-gradient-to-b from-white via-white to-slate-50/80 pt-6"
      }
    >
      {embedded ? (
        <GenericMiscEmbeddedHeader
          module={module}
          canDelete={canDelete}
          deleting={deleting}
          running={running}
          onDelete={onDelete}
        />
      ) : null}
      <GenericMiscModuleTags module={module} />
      <GenericMiscModuleCapabilities module={module} />
      {children}
    </div>
  );

  if (embedded) {
    return body;
  }

  return (
    <Card className="group relative min-w-0 overflow-visible border-cyan-100/80 bg-white shadow-[0_18px_55px_rgba(15,23,42,0.08)] ring-1 ring-cyan-50/80 transition-all duration-300 hover:-translate-y-0.5 hover:border-cyan-200 hover:shadow-[0_26px_70px_rgba(8,145,178,0.14)]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-1 rounded-t-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-indigo-500" />
      <GenericMiscCardHeader
        module={module}
        canDelete={canDelete}
        deleting={deleting}
        running={running}
        onDelete={onDelete}
      />
      <CardContent>{body}</CardContent>
    </Card>
  );
}
