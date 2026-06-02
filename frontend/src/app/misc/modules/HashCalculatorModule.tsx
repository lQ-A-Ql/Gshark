import { Hash } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { MiscModuleRendererProps } from "../types";
import { MiscModuleSurface } from "./MiscModuleSurface";
import { copyTextToClipboard } from "../../utils/browserFile";

function crc32(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

async function computeHash(algorithm: string, data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest(algorithm, data as unknown as BufferSource);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface HashResults {
  crc32: string;
  sha1: string;
  sha256: string;
}

export function HashCalculatorModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const embedded = surfaceVariant === "embedded";
  const [input, setInput] = useState("");
  const [results, setResults] = useState<HashResults | null>(null);
  const [copyNotice, setCopyNotice] = useState("");

  useEffect(() => {
    if (!input) {
      setResults(null);
      return;
    }
    let cancelled = false;
    const data = new TextEncoder().encode(input);
    const crc = crc32(input);

    void Promise.all([computeHash("SHA-1", data), computeHash("SHA-256", data)]).then(
      ([sha1, sha256]) => {
        if (cancelled) return;
        setResults({ crc32: crc, sha1, sha256 });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [input]);

  const handleCopy = useCallback(async (text: string) => {
    if (await copyTextToClipboard(text)) {
      setCopyNotice("已复制");
    } else {
      setCopyNotice("复制失败");
    }
    window.setTimeout(() => setCopyNotice(""), 1500);
  }, []);

  const rows: { label: string; value: string }[] = results
    ? [
        { label: "CRC32", value: results.crc32 },
        { label: "SHA-1", value: results.sha1 },
        { label: "SHA-256", value: results.sha256 },
      ]
    : [];

  return (
    <MiscModuleSurface module={module} embedded={embedded} icon={<Hash className="h-4 w-4" />} tone="emerald">
      <div className="space-y-1">
        <label className="text-[11px] font-medium text-slate-500">输入文本</label>
        <textarea
          className="meow-field w-full resize-none font-mono text-xs"
          rows={4}
          placeholder="在此输入待计算哈希的文本..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
      </div>

      {copyNotice && <span className="text-[11px] text-emerald-600">{copyNotice}</span>}

      {results && (
        <div className="space-y-1.5">
          {rows.map((row) => (
            <div key={row.label} className="flex items-center gap-2">
              <span className="w-16 shrink-0 text-[11px] font-medium text-slate-500">{row.label}</span>
              <code className="meow-field flex-1 truncate px-2 py-1 font-mono text-[11px]">{row.value}</code>
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
