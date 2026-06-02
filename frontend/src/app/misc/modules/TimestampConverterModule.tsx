import { Clock } from "lucide-react";
import { useState, useCallback } from "react";
import type { MiscModuleRendererProps } from "../types";
import { MiscModuleSurface } from "./MiscModuleSurface";
import { copyTextToClipboard } from "../../utils/browserFile";

interface TimestampResult {
  unixSeconds: string;
  unixMilliseconds: string;
  iso8601: string;
  locale: string;
  utc: string;
}

function parseInput(input: string): { result: TimestampResult | null; error: string } {
  if (!input.trim()) return { result: null, error: "" };
  let date: Date | null = null;

  const numVal = Number(input.trim());
  if (!isNaN(numVal) && input.trim().length > 0) {
    // Heuristic: if > 1e12, treat as milliseconds; otherwise seconds
    if (numVal > 1e12) {
      date = new Date(numVal);
    } else {
      date = new Date(numVal * 1000);
    }
  } else {
    date = new Date(input.trim());
  }

  if (!date || isNaN(date.getTime())) {
    return { result: null, error: "无法解析输入，请输入 Unix 时间戳或日期字符串" };
  }

  return {
    result: {
      unixSeconds: Math.floor(date.getTime() / 1000).toString(),
      unixMilliseconds: date.getTime().toString(),
      iso8601: date.toISOString(),
      locale: date.toLocaleString("zh-CN"),
      utc: date.toUTCString(),
    },
    error: "",
  };
}

export function TimestampConverterModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const embedded = surfaceVariant === "embedded";
  const [input, setInput] = useState("");
  const [copyNotice, setCopyNotice] = useState("");

  const { result, error } = parseInput(input);

  const fillNow = useCallback(() => {
    setInput(Math.floor(Date.now() / 1000).toString());
  }, []);

  const handleCopy = useCallback(
    async (text: string) => {
      if (await copyTextToClipboard(text)) {
        setCopyNotice("已复制");
      } else {
        setCopyNotice("复制失败");
      }
      window.setTimeout(() => setCopyNotice(""), 1500);
    },
    [],
  );

  const rows: { label: string; value: string }[] = result
    ? [
        { label: "Unix 秒", value: result.unixSeconds },
        { label: "Unix 毫秒", value: result.unixMilliseconds },
        { label: "ISO 8601", value: result.iso8601 },
        { label: "本地时间", value: result.locale },
        { label: "UTC", value: result.utc },
      ]
    : [];

  return (
    <MiscModuleSurface module={module} embedded={embedded} icon={<Clock className="h-4 w-4" />} tone="amber">
      <div className="flex items-end gap-2">
        <div className="flex-1 space-y-1">
          <label className="text-[11px] font-medium text-slate-500">时间戳或日期字符串</label>
          <input
            className="meow-field w-full font-mono text-xs"
            placeholder="如 1717315200 或 2024-06-02T12:00:00Z"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        </div>
        <button className="meow-control px-3 py-1.5 text-xs" onClick={fillNow}>
          当前时间
        </button>
      </div>

      {error && <p className="text-[11px] text-red-600">{error}</p>}
      {copyNotice && <span className="text-[11px] text-emerald-600">{copyNotice}</span>}

      {result && (
        <div className="space-y-1.5">
          {rows.map((row) => (
            <div key={row.label} className="flex items-center gap-2">
              <span className="w-20 shrink-0 text-[11px] font-medium text-slate-500">{row.label}</span>
              <code className="meow-field flex-1 truncate px-2 py-1 font-mono text-xs">{row.value}</code>
              <button
                className="meow-control px-2 py-1 text-[11px]"
                onClick={() => void handleCopy(row.value)}
              >
                复制
              </button>
            </div>
          ))}
        </div>
      )}
    </MiscModuleSurface>
  );
}
