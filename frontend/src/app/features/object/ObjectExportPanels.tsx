import { Archive, Download, Filter, Search } from "lucide-react";
import { SelectControl, type SelectOption } from "../../components/ui/select";
import { cn } from "../../components/ui/utils";
import type { ExtractedObject } from "../../core/types";
import { formatBytes } from "../../state/formatBytes";
import { classifyObject, type ObjectGroup, type ObjectKind } from "./objectExportRules";

const OBJECT_TYPE_OPTIONS: SelectOption[] = [
  { value: "all", label: "全部类型" },
  { value: "image", label: "图片" },
  { value: "text", label: "文本" },
  { value: "archive", label: "压缩包" },
  { value: "document", label: "文档" },
  { value: "executable", label: "可执行" },
  { value: "audio", label: "音频" },
  { value: "video", label: "视频" },
  { value: "unknown", label: "其他" },
];

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
    <div className="gshark-tile-toolbar flex flex-wrap items-center gap-2.5 px-3 py-2.5">
      <div className="gshark-field flex items-center gap-2 px-2 py-1">
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
        <SelectControl
          aria-label="对象类型"
          value={typeFilter}
          onValueChange={(next) => onTypeFilterChange(next as ObjectKind | "all")}
          options={OBJECT_TYPE_OPTIONS}
          size="sm"
          tone="slate"
          triggerClassName="min-w-28 text-foreground"
        />
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
    <div className="mt-2 flex flex-wrap gap-2">
      {groups.map((group) => (
        <span key={group.label} className="gshark-diffuse-chip px-2.5 py-1 text-[11px] font-medium text-slate-500">
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
    <div className="space-y-0">
      {groups.map((group) => {
        const expanded = expandedGroups[group.label] ?? false;
        const visibleItems = expanded ? group.items : group.items.slice(0, 20);
        const hasMore = group.items.length > 20;
        return (
          <section key={group.label}>
            <div className="mb-2.5 flex items-center justify-between">
              <div className="text-sm font-semibold text-foreground">{group.label}</div>
              <div className="text-[11px] text-muted-foreground">{group.items.length} 个对象</div>
            </div>
            <div className="gshark-tile-grid grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
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
                className="gshark-control mt-0 w-full py-2 text-xs text-slate-500 transition-colors hover:text-amber-700"
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
        "group gshark-tile relative flex cursor-pointer flex-col items-center justify-center p-3 transition-all",
        selected
          ? "border-blue-300 bg-blue-50/35 ring-1 ring-blue-300"
          : "bg-transparent hover:border-amber-200 hover:bg-amber-50/20",
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
    <div className="gshark-tile-toolbar flex items-center justify-between px-3 py-2.5">
      <div className="text-xs font-medium text-muted-foreground">
        已选 {selectedCount} 个文件 ({formatBytes(selectedBytes)})
      </div>
      <div className="flex gap-2.5">
        <button
          onClick={onDownloadSelected}
          disabled={selectedCount === 0}
          className="gshark-control flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium text-foreground transition-colors disabled:opacity-50"
        >
          <Download className="h-3.5 w-3.5" /> 导出选中
        </button>
        <button
          onClick={onDownloadAll}
          disabled={objectCount === 0}
          className="gshark-control-primary flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
        >
          <Archive className="h-3.5 w-3.5" /> 导出全部
        </button>
      </div>
    </div>
  );
}
