import {
  Archive,
  Binary,
  FileQuestion,
  FileText,
  Image as ImageIcon,
  Music,
  Video,
  type LucideIcon,
} from "lucide-react";
import type { ExtractedObject } from "../../core/types";

export type ObjectKind = "image" | "text" | "archive" | "executable" | "audio" | "video" | "document" | "unknown";

export interface ObjectMeta {
  icon: LucideIcon;
  color: string;
  kind: ObjectKind;
}

export interface ObjectGroup {
  label: string;
  items: ExtractedObject[];
}

export function classifyObject(item: ExtractedObject): ObjectMeta {
  const magic = (item.magic || "").toLowerCase();
  const mime = (item.mime || "").toLowerCase();

  if (magic) {
    if (magic.includes("png")) return { icon: ImageIcon, color: "text-emerald-500", kind: "image" };
    if (magic.includes("jpeg")) return { icon: ImageIcon, color: "text-blue-500", kind: "image" };
    if (magic.includes("gif")) return { icon: ImageIcon, color: "text-purple-500", kind: "image" };
    if (magic.includes("webp") || magic.includes("riff"))
      return { icon: ImageIcon, color: "text-cyan-500", kind: "image" };
    if (magic.includes("bmp")) return { icon: ImageIcon, color: "text-indigo-500", kind: "image" };
    if (magic.includes("zip") || magic.includes("docx") || magic.includes("xlsx"))
      return { icon: Archive, color: "text-amber-500", kind: "archive" };
    if (magic.includes("gzip")) return { icon: Archive, color: "text-orange-500", kind: "archive" };
    if (magic.includes("rar")) return { icon: Archive, color: "text-red-500", kind: "archive" };
    if (magic.includes("7z")) return { icon: Archive, color: "text-rose-500", kind: "archive" };
    if (magic.includes("pdf")) return { icon: FileText, color: "text-red-600", kind: "document" };
    if (magic.includes("ole") || magic.includes("doc"))
      return { icon: FileText, color: "text-blue-600", kind: "document" };
    if (magic.includes("elf") || magic.includes("pe") || magic.includes("dos") || magic.includes("mz"))
      return { icon: Binary, color: "text-slate-600", kind: "executable" };
    if (magic.includes("mp3") || magic.includes("flac") || magic.includes("ogg"))
      return { icon: Music, color: "text-pink-500", kind: "audio" };
    if (magic.includes("mp4") || magic.includes("mkv") || magic.includes("webm") || magic.includes("flv"))
      return { icon: Video, color: "text-violet-500", kind: "video" };
  }

  if (mime.startsWith("image/")) return { icon: ImageIcon, color: "text-blue-500", kind: "image" };
  if (mime.includes("zip") || mime.includes("gzip") || mime.includes("rar") || mime.includes("7z"))
    return { icon: Archive, color: "text-amber-500", kind: "archive" };
  if (mime === "application/pdf") return { icon: FileText, color: "text-red-600", kind: "document" };
  if (mime.startsWith("text/")) return { icon: FileText, color: "text-muted-foreground", kind: "text" };
  if (mime.includes("executable") || mime.includes("elf") || mime.includes("dosexec"))
    return { icon: Binary, color: "text-slate-600", kind: "executable" };
  if (mime.startsWith("audio/")) return { icon: Music, color: "text-pink-500", kind: "audio" };
  if (mime.startsWith("video/")) return { icon: Video, color: "text-violet-500", kind: "video" };

  return { icon: FileQuestion, color: "text-rose-500", kind: "unknown" };
}

export function magicGroupLabel(item: ExtractedObject): string {
  if (item.magic) {
    const magic = item.magic.toLowerCase();
    if (magic.includes("png")) return "PNG 图片";
    if (magic.includes("jpeg")) return "JPEG 图片";
    if (magic.includes("gif")) return "GIF 图片";
    if (magic.includes("webp") || magic.includes("riff")) return "WebP 图片";
    if (magic.includes("bmp")) return "BMP 图片";
    if (magic.includes("zip") || magic.includes("docx") || magic.includes("xlsx")) return "ZIP / Office";
    if (magic.includes("gzip")) return "GZIP";
    if (magic.includes("rar")) return "RAR";
    if (magic.includes("7z")) return "7z";
    if (magic.includes("pdf")) return "PDF";
    if (magic.includes("ole") || magic.includes("doc")) return "OLE2 文档";
    if (magic.includes("elf")) return "ELF 可执行";
    if (magic.includes("pe") || magic.includes("dos") || magic.includes("mz")) return "PE 可执行";
    if (magic.includes("mp3")) return "MP3";
    if (magic.includes("flac")) return "FLAC";
    if (magic.includes("mp4")) return "MP4";
    if (magic.includes("mkv") || magic.includes("webm")) return "MKV/WebM";
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

export function filterObjects(objects: ExtractedObject[], query: string, typeFilter: ObjectKind | "all") {
  const normalizedQuery = query.trim().toLowerCase();
  return objects.filter((item) => {
    const meta = classifyObject(item);
    const matchedType = typeFilter === "all" || meta.kind === typeFilter;
    const matchedQuery = !normalizedQuery || item.name.toLowerCase().includes(normalizedQuery);
    return matchedType && matchedQuery;
  });
}

export function groupObjectsByMagic(objects: ExtractedObject[]): ObjectGroup[] {
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
}
