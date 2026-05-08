import { RefreshCw } from "lucide-react";
import { Button } from "../../components/ui/button";
import type { MiscModuleManifest } from "../../core/types";
import type { MiscExportFormat } from "../exportResult";
import { ExportButtons, Field, MetaChip } from "../ui";
import { getShiroFilterLabel, shiroFilterOptions, type ShiroRememberMeCandidateFilter } from "./ShiroRememberMeUtils";
export type { ShiroRememberMeCandidateFilter } from "./ShiroRememberMeUtils";

interface ShiroRememberMeControlsProps {
  candidateCount: number;
  candidateFilter: ShiroRememberMeCandidateFilter;
  captureName: string;
  customKeyCount: number;
  customKeys: string;
  hasCapture: boolean;
  hitCount: number;
  loading: boolean;
  module: MiscModuleManifest;
  onCandidateFilterChange: (filter: ShiroRememberMeCandidateFilter) => void;
  onCustomKeysChange: (keys: string) => void;
  onExport: (format: MiscExportFormat) => void;
  onRefresh: () => void;
}

export function ShiroRememberMeControls({
  candidateCount,
  candidateFilter,
  captureName,
  customKeyCount,
  customKeys,
  hasCapture,
  hitCount,
  loading,
  module,
  onCandidateFilterChange,
  onCustomKeysChange,
  onExport,
  onRefresh,
}: ShiroRememberMeControlsProps) {
  return (
    <>
      <div className="flex flex-wrap gap-2 rounded-xl border border-amber-100 bg-amber-50/50 p-4 text-[11px] shadow-sm">
        <MetaChip label="抓包" value={hasCapture ? captureName : "未加载"} color={hasCapture ? "sky" : "slate"} />
        <MetaChip label="候选" value={candidateCount} color="slate" />
        <MetaChip label="密钥命中" value={hitCount} color={hitCount > 0 ? "rose" : "slate"} />
        <MetaChip label="自定义 Key" value={customKeyCount} color={customKeyCount > 0 ? "sky" : "slate"} />
        {module.protocolDomain && <MetaChip label="域" value={module.protocolDomain} color="slate" />}
      </div>

      <div className="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)_auto]">
        <Field label="结果筛选">
          <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
            {shiroFilterOptions.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => onCandidateFilterChange(item)}
                className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                  candidateFilter === item ? "bg-white text-amber-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                }`}
              >
                {getShiroFilterLabel(item)}
              </button>
            ))}
          </div>
        </Field>
        <Field label="自定义 AES Key">
          <textarea
            value={customKeys}
            onChange={(event) => onCustomKeysChange(event.target.value)}
            rows={3}
            placeholder="每行一个 base64 key，支持 label::base64Key"
            className="min-h-[88px] w-full resize-y rounded-xl border border-slate-200 bg-white px-3.5 py-3 font-mono text-xs leading-relaxed text-slate-800 shadow-sm outline-none transition-all placeholder:text-slate-400 focus:border-amber-300 focus:ring-4 focus:ring-amber-100/70"
          />
        </Field>
        <div className="flex items-end gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={onRefresh}
            disabled={!hasCapture || loading}
            className="gap-2 bg-white text-amber-700"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "分析中..." : "刷新 / 测试 Key"}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <ExportButtons disabled={candidateCount === 0} onExport={onExport} />
      </div>
    </>
  );
}
