import { Shield } from "lucide-react";

const EVIDENCE_HERO_TAGS = ["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"];

export function EvidenceHero() {
  return (
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="min-w-0 flex-1 space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-700 shadow-sm">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-baseline gap-2">
              <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">证据链总览</h1>
              <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">
                UNIFIED EVIDENCE
              </span>
            </div>
          </div>
        </div>
        <p className="max-w-2xl text-[13px] leading-7 text-slate-500">
          跨模块统一查看威胁狩猎、C2 分析、APT 画像、工控分析、车机分析、USB
          分析和对象导出的证据记录，支持搜索、过滤和导出。
        </p>
        <div className="flex flex-wrap gap-2 text-[11px]">
          {EVIDENCE_HERO_TAGS.map((tag) => (
            <span
              key={tag}
              className="rounded-full border border-indigo-100 bg-indigo-50/60 px-3 py-1 text-indigo-700 shadow-sm"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
