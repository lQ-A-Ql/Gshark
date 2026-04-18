import { useEffect, useMemo, useState } from "react";
import { FileDown, FileText, Image as ImageIcon, Archive, FileQuestion, Download, Filter, Search } from "lucide-react";
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
    <div className="relative flex h-full flex-col overflow-hidden bg-background p-6 text-sm text-foreground">
      <div className="mx-auto flex h-full w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-border bg-card shadow-lg">
        <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-5 py-3.5">
          <div className="flex items-center gap-2 font-semibold text-foreground">
            <FileDown className="h-5 w-5 text-amber-600" /> 提取的文件与对象
          </div>
        </div>

        <div className="z-10 flex shrink-0 items-center justify-between border-b border-border bg-card px-5 py-2.5 shadow-sm">
          <div className="flex items-center gap-3">
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
          <div className="text-xs text-muted-foreground">匹配 {objects.length} 个对象</div>
        </div>

        <div className="flex-1 overflow-auto bg-accent/20 p-5">
          <div className="mb-4 flex flex-wrap gap-2">
            {suffixGroups.map((group) => (
              <span
                key={group.label}
                className="rounded-full border border-border bg-card px-2.5 py-1 text-[11px] font-medium text-muted-foreground"
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
                          "group relative flex cursor-pointer flex-col items-center justify-center rounded-xl border bg-card p-5 transition-all",
                          isSelected
                            ? "border-blue-500 bg-blue-50/30 ring-1 ring-blue-500 shadow-md"
                            : "border-border hover:border-ring hover:shadow-sm",
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

        <div className="flex shrink-0 items-center justify-between border-t border-border bg-accent/40 px-5 py-3.5">
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
    </div>
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
