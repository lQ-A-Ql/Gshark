import { useMemo, useState } from "react";
import { FileDown, FileText, Image as ImageIcon, Archive, FileQuestion, Download, Filter, Search, Binary, Music, Video } from "lucide-react";
import { PageShell } from "../components/PageShell";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import { cn } from "../components/ui/utils";
import { bridge } from "../integrations/wailsBridge";
import type { ExtractedObject } from "../core/types";
import { useObjectExport } from "../features/object/useObjectExport";

type ObjectKind = "image" | "text" | "archive" | "executable" | "audio" | "video" | "document" | "unknown";

interface ObjectMeta {
  icon: typeof FileQuestion;
  color: string;
  kind: ObjectKind;
}

export default function ObjectExport() {
  const { extractedObjects, backendConnected } = useSentinel();
  const { objects: sourceObjects } = useObjectExport({ backendConnected, extractedObjects });
  const [selected, setSelected] = useState<number[]>([]);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<ObjectKind | "all">("all");
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  const objects = useMemo(() => {
    return sourceObjects.filter((item) => {
      const meta = classifyObject(item);
      const matchedType = typeFilter === "all" || meta.kind === typeFilter;
      const matchedQuery = !query.trim() || item.name.toLowerCase().includes(query.toLowerCase());
      return matchedType && matchedQuery;
    });
  }, [sourceObjects, query, typeFilter]);

  const selectedObjects = objects.filter((item) => selected.includes(item.id));
  const selectedBytes = selectedObjects.reduce((sum, item) => sum + item.sizeBytes, 0);
  const magicGroups = useMemo(() => {
    const groups = new Map<string, ExtractedObject[]>();
    for (const item of objects) {
      const label = magicGroupLabel(item);
      const bucket = groups.get(label) ?? [];
      bucket.push(item);
      groups.set(label, bucket);
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

  const downloadZip = async (ids: number[]) => {
    if (ids.length === 0) return;
    try {
      await bridge.downloadObjectsZip(ids);
    } catch (err) {
      console.error("下载失败:", err);
    }
  };

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(251,191,36,0.26),transparent_36%),linear-gradient(180deg,#fffaf0_0%,#fbfbff_44%,#f8fafc_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1200px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(251,191,36,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
        {/* Hero */}
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-amber-100 text-amber-700 shadow-sm">
                <FileDown className="h-5 w-5" />
              </div>
              <div>
                <div className="flex flex-wrap items-baseline gap-2">
                  <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">附件提取</h1>
                  <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">EXTRACTED OBJECTS</span>
                </div>
              </div>
            </div>
            <p className="max-w-2xl text-[13px] leading-7 text-slate-500">
              按文件类型（magic bytes）统一查看当前抓包里可导出的对象，快速筛选、分组并批量导出。
            </p>
            <div className="flex flex-wrap gap-2 text-[11px]">
              {["HTTP", "FTP", "文件对象", "Magic 分类", "批量导出"].map((tag) => (
                <span key={tag} className="rounded-full border border-amber-100 bg-amber-50/60 px-3 py-1 text-amber-700 shadow-sm">{tag}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
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
              onChange={(event) => setTypeFilter(event.target.value as ObjectKind | "all")}
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
          <div className="ml-auto text-xs text-muted-foreground">匹配 {objects.length} 个对象</div>
        </div>

        {/* Content */}
        <div className="mb-4 flex flex-wrap gap-2">
          {magicGroups.map((group) => (
            <span
              key={group.label}
              className="rounded-full border border-amber-100 bg-white/82 px-2.5 py-1 text-[11px] font-medium text-slate-500 shadow-sm"
            >
              {group.label} · {group.items.length}
            </span>
          ))}
        </div>

        <div className="space-y-6">
          {magicGroups.map((group) => {
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
                  {visibleItems.map((file) => {
                    const isSelected = selected.includes(file.id);
                    const meta = classifyObject(file);
                    const Icon = meta.icon;
                    return (
                      <div
                        key={file.id}
                        onClick={() => toggleSelect(file.id)}
                        className={cn(
                          "group relative flex cursor-pointer flex-col items-center justify-center rounded-xl p-4 transition-all",
                          isSelected
                            ? "bg-blue-50/80 ring-1 ring-blue-400 shadow-sm"
                            : "bg-slate-50/60 hover:bg-amber-50/50 hover:shadow-sm",
                        )}
                      >
                        <div className="absolute right-3 top-3">
                          <input type="checkbox" checked={isSelected} onChange={() => undefined} className="h-3.5 w-3.5 accent-blue-600" />
                        </div>
                        <Icon className={cn("mb-3 h-10 w-10", meta.color)} />
                        <div className="w-full truncate text-center text-sm font-medium text-foreground" title={file.name}>{file.name}</div>
                        <div className="mt-1 font-mono text-xs text-muted-foreground">{formatBytes(file.sizeBytes)}</div>
                        {file.magic && (
                          <div className="mt-0.5 text-[10px] text-amber-600">{file.magic}</div>
                        )}
                      </div>
                    );
                  })}
                </div>
                {hasMore && !expanded && (
                  <button
                    type="button"
                    onClick={() => setExpandedGroups((prev) => ({ ...prev, [group.label]: true }))}
                    className="mt-3 w-full rounded-xl border border-dashed border-slate-200 bg-white/60 py-2 text-xs text-slate-500 transition-colors hover:border-amber-300 hover:text-amber-700"
                  >
                    显示全部 {group.items.length} 个对象
                  </button>
                )}
              </section>
            );
          })}
        </div>

        {/* Footer */}
        <div className="mt-6 flex items-center justify-between rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
          <div className="text-xs font-medium text-muted-foreground">
            已选 {selectedObjects.length} 个文件 ({formatBytes(selectedBytes)})
          </div>
          <div className="flex gap-2.5">
            <button onClick={() => downloadZip(selectedObjects.map((o) => o.id))} disabled={selectedObjects.length === 0} className="flex items-center gap-1.5 rounded-md border border-border bg-background px-4 py-1.5 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:opacity-50">
              <Download className="h-3.5 w-3.5" /> 导出选中
            </button>
            <button onClick={() => downloadZip(objects.map((o) => o.id))} disabled={objects.length === 0} className="flex items-center gap-1.5 rounded-md border border-transparent bg-amber-600 px-4 py-1.5 text-xs font-medium text-white shadow-sm transition-colors hover:bg-amber-700 disabled:opacity-50">
              <Archive className="h-3.5 w-3.5" /> 导出全部
            </button>
          </div>
        </div>
      </section>
    </PageShell>
  );
}

function classifyObject(item: ExtractedObject): ObjectMeta {
  const magic = (item.magic || "").toLowerCase();
  const mime = (item.mime || "").toLowerCase();

  if (magic) {
    if (magic.includes("png")) return { icon: ImageIcon, color: "text-emerald-500", kind: "image" };
    if (magic.includes("jpeg")) return { icon: ImageIcon, color: "text-blue-500", kind: "image" };
    if (magic.includes("gif")) return { icon: ImageIcon, color: "text-purple-500", kind: "image" };
    if (magic.includes("webp") || magic.includes("riff")) return { icon: ImageIcon, color: "text-cyan-500", kind: "image" };
    if (magic.includes("bmp")) return { icon: ImageIcon, color: "text-indigo-500", kind: "image" };
    if (magic.includes("zip") || magic.includes("docx") || magic.includes("xlsx")) return { icon: Archive, color: "text-amber-500", kind: "archive" };
    if (magic.includes("gzip")) return { icon: Archive, color: "text-orange-500", kind: "archive" };
    if (magic.includes("rar")) return { icon: Archive, color: "text-red-500", kind: "archive" };
    if (magic.includes("7z")) return { icon: Archive, color: "text-rose-500", kind: "archive" };
    if (magic.includes("pdf")) return { icon: FileText, color: "text-red-600", kind: "document" };
    if (magic.includes("ole") || magic.includes("doc")) return { icon: FileText, color: "text-blue-600", kind: "document" };
    if (magic.includes("elf") || magic.includes("pe") || magic.includes("dos") || magic.includes("mz")) return { icon: Binary, color: "text-slate-600", kind: "executable" };
    if (magic.includes("mp3") || magic.includes("flac") || magic.includes("ogg")) return { icon: Music, color: "text-pink-500", kind: "audio" };
    if (magic.includes("mp4") || magic.includes("mkv") || magic.includes("webm") || magic.includes("flv")) return { icon: Video, color: "text-violet-500", kind: "video" };
  }

  if (mime.startsWith("image/")) return { icon: ImageIcon, color: "text-blue-500", kind: "image" };
  if (mime.includes("zip") || mime.includes("gzip") || mime.includes("rar") || mime.includes("7z")) return { icon: Archive, color: "text-amber-500", kind: "archive" };
  if (mime === "application/pdf") return { icon: FileText, color: "text-red-600", kind: "document" };
  if (mime.startsWith("text/")) return { icon: FileText, color: "text-muted-foreground", kind: "text" };
  if (mime.includes("executable") || mime.includes("elf") || mime.includes("dosexec")) return { icon: Binary, color: "text-slate-600", kind: "executable" };
  if (mime.startsWith("audio/")) return { icon: Music, color: "text-pink-500", kind: "audio" };
  if (mime.startsWith("video/")) return { icon: Video, color: "text-violet-500", kind: "video" };

  return { icon: FileQuestion, color: "text-rose-500", kind: "unknown" };
}

function magicGroupLabel(item: ExtractedObject): string {
  if (item.magic) {
    const m = item.magic.toLowerCase();
    if (m.includes("png")) return "PNG 图片";
    if (m.includes("jpeg")) return "JPEG 图片";
    if (m.includes("gif")) return "GIF 图片";
    if (m.includes("webp") || m.includes("riff")) return "WebP 图片";
    if (m.includes("bmp")) return "BMP 图片";
    if (m.includes("zip") || m.includes("docx") || m.includes("xlsx")) return "ZIP / Office";
    if (m.includes("gzip")) return "GZIP";
    if (m.includes("rar")) return "RAR";
    if (m.includes("7z")) return "7z";
    if (m.includes("pdf")) return "PDF";
    if (m.includes("ole") || m.includes("doc")) return "OLE2 文档";
    if (m.includes("elf")) return "ELF 可执行";
    if (m.includes("pe") || m.includes("dos") || m.includes("mz")) return "PE 可执行";
    if (m.includes("mp3")) return "MP3";
    if (m.includes("flac")) return "FLAC";
    if (m.includes("mp4")) return "MP4";
    if (m.includes("mkv") || m.includes("webm")) return "MKV/WebM";
    return item.magic;
  }

  const mime = (item.mime || "").toLowerCase();
  if (mime.startsWith("image/")) return `图片 (${mime.slice(6)})`;
  if (mime.includes("zip")) return "压缩包";
  if (mime === "application/pdf") return "PDF";
  if (mime.startsWith("text/")) return "文本";
  if (mime.startsWith("audio/")) return "音频";
  if (mime.startsWith("video/")) return "视频";
  return "未知类型";
}
