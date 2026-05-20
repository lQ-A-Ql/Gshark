import type { ReactNode } from "react";
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
    <div className={embedded ? "space-y-4" : "space-y-4"}>
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
    <section className="gshark-tile gshark-diffuse-edge gshark-workbench-panel group relative min-w-0 overflow-visible transition-colors duration-300">
      <GenericMiscCardHeader
        module={module}
        canDelete={canDelete}
        deleting={deleting}
        running={running}
        onDelete={onDelete}
      />
      <div className="p-4">{body}</div>
    </section>
  );
}
