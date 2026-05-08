import type { ReactNode } from "react";
import { Loader2, Trash2 } from "lucide-react";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import type { MiscModuleManifest } from "../../core/types";

interface DeleteActionProps {
  canDelete: boolean;
  deleting: boolean;
  running: boolean;
  onDelete: () => void;
  variant: "embedded" | "card";
}

interface GenericMiscModuleChromeProps {
  module: MiscModuleManifest;
  surfaceVariant: "card" | "embedded";
  children: ReactNode;
  canDelete: boolean;
  deleting: boolean;
  running: boolean;
  onDelete: () => void;
}

function buildTags(module: MiscModuleManifest) {
  const runtime = module.interfaceSchema?.runtime ? [`Runtime:${module.interfaceSchema.runtime}`] : [];
  return [...module.tags, ...runtime];
}

function DeleteAction({ canDelete, deleting, running, onDelete, variant }: DeleteActionProps) {
  if (!canDelete) return null;

  const className =
    variant === "embedded"
      ? "border-rose-200 bg-white text-rose-700 shadow-sm hover:bg-rose-50"
      : "border-rose-200 bg-white/80 text-rose-600 shadow-sm backdrop-blur hover:border-rose-300 hover:bg-rose-50 hover:text-rose-700";

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      onClick={onDelete}
      disabled={deleting || running}
    >
      {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
      {deleting ? "删除中..." : "删除模块"}
    </Button>
  );
}

function EmbeddedHeader({
  module,
  canDelete,
  deleting,
  running,
  onDelete,
}: Pick<GenericMiscModuleChromeProps, "module" | "canDelete" | "deleting" | "running" | "onDelete">) {
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
      <DeleteAction
        canDelete={canDelete}
        deleting={deleting}
        running={running}
        onDelete={onDelete}
        variant="embedded"
      />
    </div>
  );
}

function ModuleTags({ module }: { module: MiscModuleManifest }) {
  return (
    <div className="flex flex-wrap gap-2">
      {buildTags(module).map((tag) => (
        <Badge
          key={`${module.id}-${tag}`}
          variant="outline"
          className="rounded-full border-cyan-100 bg-cyan-50/70 px-2.5 py-1 text-[11px] font-semibold text-cyan-800 shadow-sm"
        >
          {tag}
        </Badge>
      ))}
    </div>
  );
}

function ModuleCapabilities({ module }: { module: MiscModuleManifest }) {
  return (
    <div className="flex flex-wrap gap-2 text-[11px]">
      <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
        {module.requiresCapture ? "需要抓包" : "无需抓包"}
      </Badge>
      {module.protocolDomain ? (
        <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
          域: {module.protocolDomain}
        </Badge>
      ) : null}
      {module.supportsExport ? (
        <Badge variant="outline" className="rounded-full border-emerald-200 bg-emerald-50 text-emerald-700">
          支持导出
        </Badge>
      ) : null}
      <Badge
        variant="outline"
        title={
          module.cancellable
            ? "该模块的分析请求支持中途取消或切换时自动中断"
            : "该模块当前按同步请求执行，没有单独的中断能力位"
        }
        className={`rounded-full ${module.cancellable ? "border-amber-200 bg-amber-50 text-amber-700" : "border-slate-200 bg-slate-50 text-slate-700"}`}
      >
        {module.cancellable ? "支持中断" : "同步执行"}
      </Badge>
      {(module.dependsOn?.length ?? 0) > 0 ? (
        <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
          依赖: {module.dependsOn!.join(", ")}
        </Badge>
      ) : null}
    </div>
  );
}

function CardHeaderContent({
  module,
  canDelete,
  deleting,
  running,
  onDelete,
}: Pick<GenericMiscModuleChromeProps, "module" | "canDelete" | "deleting" | "running" | "onDelete">) {
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
        <DeleteAction canDelete={canDelete} deleting={deleting} running={running} onDelete={onDelete} variant="card" />
      </div>
      <CardDescription className="max-w-3xl text-[13px] leading-relaxed text-slate-600">
        {module.summary}
      </CardDescription>
    </CardHeader>
  );
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
        <EmbeddedHeader
          module={module}
          canDelete={canDelete}
          deleting={deleting}
          running={running}
          onDelete={onDelete}
        />
      ) : null}
      <ModuleTags module={module} />
      <ModuleCapabilities module={module} />
      {children}
    </div>
  );

  if (embedded) {
    return body;
  }

  return (
    <Card className="group relative min-w-0 overflow-visible border-cyan-100/80 bg-white shadow-[0_18px_55px_rgba(15,23,42,0.08)] ring-1 ring-cyan-50/80 transition-all duration-300 hover:-translate-y-0.5 hover:border-cyan-200 hover:shadow-[0_26px_70px_rgba(8,145,178,0.14)]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-1 rounded-t-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-indigo-500" />
      <CardHeaderContent
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
