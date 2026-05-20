import { Badge } from "../../components/ui/badge";
import type { MiscModuleManifest } from "../../core/types";
import { GenericMiscDeleteAction } from "./GenericMiscDeleteAction";

interface GenericMiscModuleHeaderProps {
  module: MiscModuleManifest;
  canDelete: boolean;
  deleting: boolean;
  running: boolean;
  onDelete: () => void;
}

export function GenericMiscEmbeddedHeader({
  module,
  canDelete,
  deleting,
  running,
  onDelete,
}: GenericMiscModuleHeaderProps) {
  return (
    <div className="gshark-tile-toolbar flex flex-wrap items-start justify-between gap-3 border-cyan-100/24 bg-cyan-50/18 px-4 py-3">
      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="border-cyan-200/28 bg-cyan-50/20 text-cyan-800">
            {module.kind === "custom" ? "Custom" : "Builtin"}
          </Badge>
          {module.interfaceSchema?.runtime ? (
            <Badge variant="outline" className="border-cyan-200/28 bg-cyan-50/20 text-cyan-800">
              {module.interfaceSchema.runtime}
            </Badge>
          ) : null}
        </div>
        {module.formSchema?.description ? (
          <div className="text-[13px] leading-relaxed text-slate-600">{module.formSchema.description}</div>
        ) : null}
      </div>
      <GenericMiscDeleteAction
        canDelete={canDelete}
        deleting={deleting}
        running={running}
        onDelete={onDelete}
        variant="embedded"
      />
    </div>
  );
}

export function GenericMiscCardHeader({
  module,
  canDelete,
  deleting,
  running,
  onDelete,
}: GenericMiscModuleHeaderProps) {
  return (
    <div className="gshark-tile-header relative border-b border-cyan-100/24 bg-cyan-50/18 px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-cyan-200/28 bg-cyan-50/20 text-cyan-700">
              {module.kind === "custom" ? "Custom" : "Builtin"}
            </Badge>
            {module.interfaceSchema?.runtime ? (
              <Badge variant="outline" className="border-blue-200/28 bg-blue-50/20 text-blue-700">
                {module.interfaceSchema.runtime}
              </Badge>
            ) : null}
          </div>
          <h2 className="break-words text-lg font-semibold tracking-tight text-slate-900">{module.title}</h2>
        </div>
        <GenericMiscDeleteAction
          canDelete={canDelete}
          deleting={deleting}
          running={running}
          onDelete={onDelete}
          variant="card"
        />
      </div>
      <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-slate-600">{module.summary}</p>
    </div>
  );
}
