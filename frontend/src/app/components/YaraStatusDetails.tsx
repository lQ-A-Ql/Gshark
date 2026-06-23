import type { ToolRuntimeSnapshot } from "../core/types";

export function YaraStatusDetails({ yara }: { yara?: ToolRuntimeSnapshot["yara"] }) {
  return (
    <>
      {yara?.rulePath ? (
        <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px] leading-5 text-slate-500">
          当前使用的规则文件：
          <span className="break-all text-slate-700"> {yara.rulePath}</span>
        </div>
      ) : null}
      {yara?.lastScanMessage ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-5 text-amber-700">
          最近一次扫描告警：
          <span className="break-all"> {yara.lastScanMessage}</span>
        </div>
      ) : null}
    </>
  );
}
