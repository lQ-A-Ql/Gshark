import { useEffect, useMemo, useState } from "react";
import { FileDown, FileText, Image as ImageIcon, Archive, FileQuestion, Download, Filter, Search } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import { cn } from "../components/ui/utils";
import { bridge, getBackendAuthHeaders } from "../integrations/wailsBridge";
import type { ExtractedObject } from "../core/types";

function iconForMime(mime: string) {
  if (mime.startsWith("image/")) return { icon: ImageIcon, color: "text-blue-500", kind: "image" };
  if (mime.includes("zip")) return { icon: Archive, color: "text-amber-500", kind: "archive" };
  if (mime.startsWith("text/")) return { icon: FileText, color: "text-muted-foreground", kind: "text" };
  return { icon: FileQuestion, color: "text-rose-500", kind: "unknown" };
}

export default function ObjectExport() {
  const { extractedObjects, backendConnected } = useSentinel();
  const [fallbackObjects, setFallbackObjects] = useState<ExtractedObject[] | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "image" | "text" | "archive" | "unknown">("all");

  useEffect(() => {
    if (!backendConnected) {
      setFallbackObjects(null);
      return;
    }
    if (extractedObjects.length > 0) {
      setFallbackObjects(null);
      return;
    }

    let cancelled = false;
    void bridge.listObjects()
      .then((rows) => {
        if (!cancelled && rows.length > 0) {
          setFallbackObjects(rows);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFallbackObjects(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [backendConnected, extractedObjects]);

  const sourceObjects = extractedObjects.length > 0 ? extractedObjects : (fallbackObjects ?? []);

  const objects = useMemo(() => {
    return sourceObjects.filter((item) => {
      const meta = iconForMime(item.mime);
      const matchedType = typeFilter === "all" || meta.kind === typeFilter;
      const matchedQuery = !query.trim() || item.name.toLowerCase().includes(query.toLowerCase());
      return matchedType && matchedQuery;
    });
  }, [sourceObjects, query, typeFilter]);

  const selectedObjects = objects.filter((item) => selected.includes(item.id));
  const selectedBytes = selectedObjects.reduce((sum, item) => sum + item.sizeBytes, 0);
  const suffixGroups = useMemo(() => {
    const groups = new Map<string, ExtractedObject[]>();
    for (const item of objects) {
      const suffix = extensionLabelForObject(item);
      const bucket = groups.get(suffix) ?? [];
      bucket.push(item);
      groups.set(suffix, bucket);
    }
    return Array.from(groups.entries())
      .map(([label, items]) => ({
        label,
        items: [...items].sort((a, b) => a.name.localeCompare(b.name, "zh-CN")),
      }))
      .sort((a, b) => b.items.length - a.items.length || a.label.localeCompare(b.label, "zh-CN"));
  }, [objects]);

  const toggleSelect = (id: number) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://127.0.0.1:17891";

  const downloadZip = async (ids: number[]) => {
    if (ids.length === 0) return;
    try {
      const body = JSON.stringify({ ids });
      const headers = await getBackendAuthHeaders("/api/objects/download", { "Content-Type": "application/json" }, body);
      const resp = await fetch(`${BACKEND_URL}/api/objects/download`, {
        method: "POST",
        headers,
        body,
      });
      if (!resp.ok) throw new Error("Download failed");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "exported_objects.zip";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("下载失败:", err);
    }
  };

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(251,191,36,0.26),transparent_36%),linear-gradient(180deg,#fffaf0_0%,#fbfbff_44%,#f8fafc_100%)]"
      innerClassName="max-w-6xl px-6 py-6"
    >
      <AnalysisHero
        icon={<FileDown className="h-5 w-5" />}
        title="附件提取"
        subtitle="EXTRACTED OBJECTS"
        description="按类型与后缀统一查看当前抓包里可导出的对象，快速筛选、分组并批量导出。"
        tags={["HTTP", "FTP", "文件对象", "批量导出"]}
        tagsLabel="导出域"
        theme="amber"
      />
      <div className="flex h-full w-full flex-col overflow-hidden rounded-[28px] border border-white/80 bg-white/88 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl">
        <div className="z-10 flex shrink-0 items-center justify-between border-b border-slate-100 bg-white/82 px-5 py-3 shadow-sm backdrop-blur-xl">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1 shadow-sm focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
              <Search className="h-4 w-4 text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="按文件名搜索"
                className="border-none bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <select
                value={typeFilter}
                onChange={(event) => setTypeFilter(event.target.value as typeof typeFilter)}
                className="cursor-pointer rounded-md border border-border bg-accent px-2.5 py-1.5 text-xs text-foreground outline-none transition-all focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="all">全部类型</option>
                <option value="image">图片</option>
                <option value="text">文本</option>
                <option value="archive">压缩包</option>
                <option value="unknown">其他</option>
              </select>
            </div>
          </div>
          <div className="shrink-0 text-xs text-muted-foreground">匹配 {objects.length} 个对象</div>
        </div>

        <div className="flex-1 overflow-auto bg-slate-50/45 p-5">
          <div className="mb-4 flex flex-wrap gap-2">
            {suffixGroups.map((group) => (
              <span
                key={group.label}
                className="rounded-full border border-amber-100 bg-white/82 px-2.5 py-1 text-[11px] font-medium text-slate-500 shadow-sm"
              >
                {group.label} · {group.items.length}
              </span>
            ))}
          </div>
          <div className="space-y-6">
            {suffixGroups.map((group) => (
              <section key={group.label}>
                <div className="mb-3 flex items-center justify-between">
                  <div className="text-sm font-semibold text-foreground">后缀 {group.label}</div>
                  <div className="text-[11px] text-muted-foreground">{group.items.length} 个对象</div>
                </div>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
                  {group.items.map((file) => {
                    const isSelected = selected.includes(file.id);
                    const meta = iconForMime(file.mime);
                    const Icon = meta.icon;
                    return (
                      <div
                        key={file.id}
                        onClick={() => toggleSelect(file.id)}
                        className={cn(
                          "group relative flex cursor-pointer flex-col items-center justify-center rounded-2xl border bg-white/86 p-5 shadow-sm transition-all",
                          isSelected
                            ? "border-blue-500 bg-blue-50/30 ring-1 ring-blue-500 shadow-md"
                            : "border-slate-100 hover:border-amber-200 hover:shadow-md",
                        )}
                      >
                        <div className="absolute right-3 top-3">
                          <input type="checkbox" checked={isSelected} onChange={() => undefined} className="h-3.5 w-3.5 accent-blue-600" />
                        </div>
                        <Icon className={cn("mb-3 h-10 w-10", meta.color)} />
                        <div className="w-full truncate text-center text-sm font-medium text-foreground" title={file.name}>{file.name}</div>
                        <div className="mt-1 font-mono text-xs text-muted-foreground">{formatBytes(file.sizeBytes)}</div>
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
        </div>

        <div className="flex shrink-0 items-center justify-between border-t border-slate-100 bg-white/82 px-5 py-3.5 backdrop-blur-xl">
          <div className="text-xs font-medium text-muted-foreground">
            已选 {selectedObjects.length} 个文件 ({formatBytes(selectedBytes)})
          </div>
          <div className="flex gap-2.5">
            <button onClick={() => downloadZip(selectedObjects.map((o) => o.id))} disabled={selectedObjects.length === 0} className="flex items-center gap-1.5 rounded-md border border-border bg-background px-4 py-1.5 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:opacity-50">
              <Download className="h-3.5 w-3.5" /> 导出选中
            </button>
            <button onClick={() => downloadZip(objects.map((o) => o.id))} disabled={objects.length === 0} className="flex items-center gap-1.5 rounded-md border border-transparent bg-blue-600 px-4 py-1.5 text-xs font-medium text-white shadow-sm transition-colors hover:bg-blue-700 disabled:opacity-50">
              <Archive className="h-3.5 w-3.5" /> 导出全部
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}

function extensionLabelForObject(item: ExtractedObject): string {
  const match = item.name.toLowerCase().match(/\.([a-z0-9]{1,12})$/i);
  if (match?.[1]) {
    return `.${match[1]}`;
  }

  if (item.mime.startsWith("image/")) {
    return `.${item.mime.slice("image/".length).toLowerCase()}`;
  }
  if (item.mime.includes("zip")) {
    return ".zip";
  }
  return "(无后缀)";
}
