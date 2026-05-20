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
          className="gshark-diffuse-chip px-2.5 py-1 text-[11px] font-semibold text-cyan-800"
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
      <Badge variant="outline" className="gshark-diffuse-chip text-slate-700">
        {module.requiresCapture ? "需要抓包" : "无需抓包"}
      </Badge>
      {module.protocolDomain ? (
        <Badge variant="outline" className="gshark-diffuse-chip text-slate-700">
          域: {module.protocolDomain}
        </Badge>
      ) : null}
      {module.supportsExport ? (
        <Badge variant="outline" className="gshark-diffuse-chip text-emerald-700">
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
        className={module.cancellable ? "gshark-diffuse-chip text-amber-700" : "gshark-diffuse-chip text-slate-700"}
      >
        {module.cancellable ? "支持中断" : "同步执行"}
      </Badge>
      {(module.dependsOn?.length ?? 0) > 0 ? (
        <Badge variant="outline" className="gshark-diffuse-chip text-slate-700">
          依赖: {module.dependsOn!.join(", ")}
        </Badge>
      ) : null}
    </div>
  );
}
