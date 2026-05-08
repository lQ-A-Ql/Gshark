import type { RecentCapture } from "../core/types";

export interface OpenedCapture {
  filePath: string;
  fileName: string;
  fileSize?: number;
}

export interface CaptureFileMeta {
  name: string;
  sizeBytes: number;
  path: string;
}

export function createInitialCaptureFileMeta(): CaptureFileMeta {
  return {
    name: "",
    sizeBytes: 0,
    path: "",
  };
}

export function createClosedCaptureFileMeta(): CaptureFileMeta {
  return {
    name: "未打开文件",
    sizeBytes: 0,
    path: "",
  };
}

export function buildOpenedCaptureFromPath(filePath: string): OpenedCapture | null {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return null;

  return {
    filePath: normalizedPath,
    fileSize: 0,
    fileName: normalizedPath.split(/[\\/]/).pop() ?? "capture.pcapng",
  };
}

export function buildCaptureFileMeta(opened: OpenedCapture): CaptureFileMeta {
  return {
    name: opened.fileName,
    sizeBytes: Number(opened.fileSize ?? 0),
    path: opened.filePath,
  };
}

export function buildRecentCapture(opened: OpenedCapture, lastOpenedAt: string): RecentCapture {
  return {
    path: opened.filePath,
    name: opened.fileName,
    sizeBytes: Number(opened.fileSize ?? 0),
    lastOpenedAt,
  };
}
