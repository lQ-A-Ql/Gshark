import { Badge } from "../../components/ui/badge";
import type { MiscModuleManifest } from "../../core/types";

function buildTags(module: MiscModuleManifest) {
  const runtime = module.interfaceSchema?.runtime ? [`Runtime:${module.interfaceSchema.runtime}`] : [];
  return [...module.tags, ...runtime];
}

export function GenericMiscModuleTags({ module }: { module: MiscModuleManifest }) {
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

export function GenericMiscModuleCapabilities({ module }: { module: MiscModuleManifest }) {
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
