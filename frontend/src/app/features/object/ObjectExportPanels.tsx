import { Archive, Download, FileDown, Filter, Search } from "lucide-react";
import { cn } from "../../components/ui/utils";
import type { ExtractedObject } from "../../core/types";
import { formatBytes } from "../../state/SentinelContext";
import { classifyObject, type ObjectGroup, type ObjectKind } from "./objectExportRules";

interface ObjectExportHeroProps {
  tags: string[];
}

export function ObjectExportHero({ tags }: ObjectExportHeroProps) {
  return (
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="min-w-0 flex-1 space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-amber-100 text-amber-700 shadow-sm">
            <FileDown className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-baseline gap-2">
              <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">附件提取</h1>
              <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">
                EXTRACTED OBJECTS
              </span>
            </div>
          </div>
        </div>
        <p className="max-w-2xl text-[13px] leading-7 text-slate-500">
          按文件类型（magic bytes）统一查看当前抓包里可导出的对象，快速筛选、分组并批量导出。
        </p>
        <div className="flex flex-wrap gap-2 text-[11px]">
          {tags.map((tag) => (
            <span
              key={tag}
              className="rounded-full border border-amber-100 bg-amber-50/60 px-3 py-1 text-amber-700 shadow-sm"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

interface ObjectExportToolbarProps {
  count: number;
  query: string;
  typeFilter: ObjectKind | "all";
  onQueryChange: (query: string) => void;
  onTypeFilterChange: (kind: ObjectKind | "all") => void;
}

export function ObjectExportToolbar({
  count,
  query,
  typeFilter,
  onQueryChange,
  onTypeFilterChange,
}: ObjectExportToolbarProps) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
      <div className="flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1 shadow-sm focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
        <Search className="h-4 w-4 text-muted-foreground" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="按文件名搜索"
          className="border-none bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
        />
      </div>
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <select
          value={typeFilter}
          onChange={(event) => onTypeFilterChange(event.target.value as ObjectKind | "all")}
          className="cursor-pointer rounded-md border border-border bg-accent px-2.5 py-1.5 text-xs text-foreground outline-none transition-all focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        >
          <option value="all">全部类型</option>
          <option value="image">图片</option>
          <option value="text">文本</option>
          <option value="archive">压缩包</option>
          <option value="document">文档</option>
          <option value="executable">可执行</option>
          <option value="audio">音频</option>
          <option value="video">视频</option>
          <option value="unknown">其他</option>
        </select>
      </div>
      <div className="ml-auto text-xs text-muted-foreground">匹配 {count} 个对象</div>
    </div>
  );
}

interface ObjectGroupChipsProps {
  groups: ObjectGroup[];
}

export function ObjectGroupChips({ groups }: ObjectGroupChipsProps) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {groups.map((group) => (
        <span
          key={group.label}
          className="rounded-full border border-amber-100 bg-white/82 px-2.5 py-1 text-[11px] font-medium text-slate-500 shadow-sm"
        >
          {group.label} · {group.items.length}
        </span>
      ))}
    </div>
  );
}

interface ObjectGroupGridProps {
  expandedGroups: Record<string, boolean>;
  groups: ObjectGroup[];
  selectedIds: number[];
  onExpandGroup: (label: string) => void;
  onToggleSelect: (id: number) => void;
}

export function ObjectGroupGrid({
  expandedGroups,
  groups,
  selectedIds,
  onExpandGroup,
  onToggleSelect,
}: ObjectGroupGridProps) {
  return (
    <div className="space-y-6">
      {groups.map((group) => {
        const expanded = expandedGroups[group.label] ?? false;
        const visibleItems = expanded ? group.items : group.items.slice(0, 20);
        const hasMore = group.items.length > 20;
        return (
          <section key={group.label}>
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold text-foreground">{group.label}</div>
              <div className="text-[11px] text-muted-foreground">{group.items.length} 个对象</div>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
              {visibleItems.map((file) => (
                <ObjectCard
                  key={file.id}
                  file={file}
                  selected={selectedIds.includes(file.id)}
                  onToggleSelect={onToggleSelect}
                />
              ))}
            </div>
            {hasMore && !expanded && (
              <button
                type="button"
                onClick={() => onExpandGroup(group.label)}
                className="mt-3 w-full rounded-xl border border-dashed border-slate-200 bg-white/60 py-2 text-xs text-slate-500 transition-colors hover:border-amber-300 hover:text-amber-700"
              >
                显示全部 {group.items.length} 个对象
              </button>
            )}
          </section>
        );
      })}
    </div>
  );
}

interface ObjectCardProps {
  file: ExtractedObject;
  selected: boolean;
  onToggleSelect: (id: number) => void;
}

function ObjectCard({ file, selected, onToggleSelect }: ObjectCardProps) {
  const meta = classifyObject(file);
  const Icon = meta.icon;

  return (
    <div
      onClick={() => onToggleSelect(file.id)}
      className={cn(
        "group relative flex cursor-pointer flex-col items-center justify-center rounded-xl p-4 transition-all",
        selected
          ? "bg-blue-50/80 ring-1 ring-blue-400 shadow-sm"
          : "bg-slate-50/60 hover:bg-amber-50/50 hover:shadow-sm",
      )}
    >
      <div className="absolute right-3 top-3">
        <input type="checkbox" checked={selected} onChange={() => undefined} className="h-3.5 w-3.5 accent-blue-600" />
      </div>
      <Icon className={cn("mb-3 h-10 w-10", meta.color)} />
      <div className="w-full truncate text-center text-sm font-medium text-foreground" title={file.name}>
        {file.name}
      </div>
      <div className="mt-1 font-mono text-xs text-muted-foreground">{formatBytes(file.sizeBytes)}</div>
      {file.magic && <div className="mt-0.5 text-[10px] text-amber-600">{file.magic}</div>}
    </div>
  );
}

interface ObjectExportFooterProps {
  objectCount: number;
  selectedBytes: number;
  selectedCount: number;
  onDownloadAll: () => void;
  onDownloadSelected: () => void;
}

export function ObjectExportFooter({
  objectCount,
  selectedBytes,
  selectedCount,
  onDownloadAll,
  onDownloadSelected,
}: ObjectExportFooterProps) {
  return (
    <div className="mt-6 flex items-center justify-between rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
      <div className="text-xs font-medium text-muted-foreground">
        已选 {selectedCount} 个文件 ({formatBytes(selectedBytes)})
      </div>
      <div className="flex gap-2.5">
        <button
          onClick={onDownloadSelected}
          disabled={selectedCount === 0}
          className="flex items-center gap-1.5 rounded-md border border-border bg-background px-4 py-1.5 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:opacity-50"
        >
          <Download className="h-3.5 w-3.5" /> 导出选中
        </button>
        <button
          onClick={onDownloadAll}
          disabled={objectCount === 0}
          className="flex items-center gap-1.5 rounded-md border border-transparent bg-amber-600 px-4 py-1.5 text-xs font-medium text-white shadow-sm transition-colors hover:bg-amber-700 disabled:opacity-50"
        >
          <Archive className="h-3.5 w-3.5" /> 导出全部
        </button>
      </div>
    </div>
  );
}
