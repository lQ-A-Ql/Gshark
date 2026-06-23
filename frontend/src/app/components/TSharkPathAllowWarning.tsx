import { useState } from "react";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import type { ToolRuntimeSnapshot } from "../core/types";

type ToolPathWarningStatus = {
  path?: string;
  customPath?: string;
  pathWarning?: string;
};

function getDirToAllow(status: ToolPathWarningStatus): string {
  const candidate = (status.customPath || status.path || "").trim();
  if (!candidate) return "";
  const normalized = candidate.replace(/\\/g, "/");
  const lastSlash = normalized.lastIndexOf("/");
  if (lastSlash < 0) return candidate;
  const raw = candidate.slice(0, lastSlash + 1);
  const cleaned = raw.replace(/[\\/]+$/, "");
  // Keep the trailing separator for drive roots (C:\) or filesystem root (/).
  if (cleaned === "" || (cleaned.length === 2 && cleaned[1] === ":")) {
    return raw;
  }
  return cleaned;
}

interface TSharkPathAllowWarningProps {
  status?: ToolRuntimeSnapshot["tshark"] | null;
  allowTSharkDir?: (dir: string) => Promise<TSharkStatus>;
}

export function TSharkPathAllowWarning({ status, allowTSharkDir }: TSharkPathAllowWarningProps) {
  return <ToolPathAllowWarning status={status} allowDir={allowTSharkDir} />;
}

interface ToolPathAllowWarningProps {
  status?: ToolPathWarningStatus | null;
  allowDir?: (dir: string) => Promise<unknown>;
}

export function ToolPathAllowWarning({ status, allowDir }: ToolPathAllowWarningProps) {
  const [isAllowing, setIsAllowing] = useState(false);
  if (!status?.pathWarning) return null;
  const dir = getDirToAllow(status);
  if (!dir) return null;
  const handleAllow = async () => {
    if (!allowDir) return;
    setIsAllowing(true);
    try {
      await allowDir(dir);
    } finally {
      setIsAllowing(false);
    }
  };
  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-5 text-amber-800">
      <div className="flex items-start justify-between gap-3">
        <span className="break-all">⚠️ {status.pathWarning}</span>
        <button
          type="button"
          onClick={handleAllow}
          disabled={isAllowing}
          className="shrink-0 rounded-md bg-amber-100 px-2.5 py-1 text-[11px] font-medium text-amber-900 transition hover:bg-amber-200 disabled:opacity-50"
        >
          {isAllowing ? "处理中..." : "加入白名单"}
        </button>
      </div>
      <div className="mt-1 break-all text-amber-700/80">目录：{dir}</div>
    </div>
  );
}
