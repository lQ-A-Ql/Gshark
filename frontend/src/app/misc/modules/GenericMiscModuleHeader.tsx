import { Badge } from "../../components/ui/badge";
import { CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
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
    <div className="flex flex-wrap items-start justify-between gap-3 rounded-2xl border border-cyan-100 bg-gradient-to-r from-cyan-50 via-sky-50 to-white px-4 py-3">
      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="border-cyan-200 bg-white text-cyan-800 shadow-sm">
            {module.kind === "custom" ? "Custom" : "Builtin"}
          </Badge>
          {module.interfaceSchema?.runtime ? (
            <Badge variant="outline" className="border-cyan-200 bg-white text-cyan-800 shadow-sm">
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
    <CardHeader className="relative gap-3 rounded-t-xl border-b border-cyan-100/70 bg-[radial-gradient(circle_at_12%_20%,rgba(34,211,238,0.22),transparent_34%),linear-gradient(135deg,#f8fafc_0%,#ecfeff_52%,#eff6ff_100%)] pb-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-cyan-200 bg-white/80 text-cyan-700 shadow-sm backdrop-blur">
              {module.kind === "custom" ? "Custom" : "Builtin"}
            </Badge>
            {module.interfaceSchema?.runtime ? (
              <Badge variant="outline" className="border-blue-200 bg-blue-50 text-blue-700 shadow-sm backdrop-blur">
                {module.interfaceSchema.runtime}
              </Badge>
            ) : null}
          </div>
          <CardTitle className="break-words text-lg font-semibold tracking-tight text-slate-900">
            {module.title}
          </CardTitle>
        </div>
        <GenericMiscDeleteAction
          canDelete={canDelete}
          deleting={deleting}
          running={running}
          onDelete={onDelete}
          variant="card"
        />
      </div>
      <CardDescription className="max-w-3xl text-[13px] leading-relaxed text-slate-600">
        {module.summary}
      </CardDescription>
    </CardHeader>
  );
}
