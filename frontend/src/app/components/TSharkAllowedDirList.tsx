import { X } from "lucide-react";
import { useEffect, useState } from "react";

interface TSharkAllowedDirListProps {
  dirs: string[];
  onRemove?: (dir: string) => Promise<unknown>;
  onRefresh?: () => Promise<unknown>;
}

export function TSharkAllowedDirList({ dirs, onRemove, onRefresh }: TSharkAllowedDirListProps) {
  const [removingDir, setRemovingDir] = useState<string | null>(null);

  useEffect(() => {
    if (onRefresh) void onRefresh();
  }, [onRefresh]);

  if (dirs.length === 0) return null;

  const handleRemove = async (dir: string) => {
    if (!onRemove) return;
    setRemovingDir(dir);
    try {
      await onRemove(dir);
    } finally {
      setRemovingDir(null);
    }
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
      <div className="mb-1.5 text-[11px] font-medium text-slate-600">已允许目录</div>
      <ul className="space-y-1.5">
        {dirs.map((dir) => (
          <li
            key={dir}
            className="flex items-center justify-between gap-2 rounded-lg bg-white px-2.5 py-1.5 text-[11px] text-slate-700 shadow-sm"
          >
            <span className="break-all">{dir}</span>
            <button
              type="button"
              disabled={removingDir === dir || !onRemove}
              onClick={() => void handleRemove(dir)}
              className="shrink-0 rounded-md p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600 disabled:opacity-50"
              title="移除"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
