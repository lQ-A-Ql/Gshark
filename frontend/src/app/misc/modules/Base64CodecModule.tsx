import { Binary } from "lucide-react";
import { useState, useCallback } from "react";
import { Textarea } from "../../components/ui/textarea";
import type { MiscModuleRendererProps } from "../types";
import { MiscModuleSurface } from "./MiscModuleSurface";
import { copyTextToClipboard } from "../../utils/browserFile";

type CodecMode = "base64-encode" | "base64-decode" | "hex-encode" | "hex-decode" | "url-encode" | "url-decode";

const modes: { value: CodecMode; label: string }[] = [
  { value: "base64-encode", label: "Base64 编码" },
  { value: "base64-decode", label: "Base64 解码" },
  { value: "hex-encode", label: "Hex 编码" },
  { value: "hex-decode", label: "Hex 解码" },
  { value: "url-encode", label: "URL 编码" },
  { value: "url-decode", label: "URL 解码" },
];

function convert(input: string, mode: CodecMode): { result: string; error: string } {
  if (!input) return { result: "", error: "" };
  try {
    switch (mode) {
      case "base64-encode":
        return { result: btoa(unescape(encodeURIComponent(input))), error: "" };
      case "base64-decode":
        return { result: decodeURIComponent(escape(atob(input.trim()))), error: "" };
      case "hex-encode":
        return {
          result: Array.from(new TextEncoder().encode(input))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
          error: "",
        };
      case "hex-decode": {
        const hex = input.replace(/\s/g, "");
        if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
          return { result: "", error: "无效的 Hex 字符串" };
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return { result: new TextDecoder().decode(bytes), error: "" };
      }
      case "url-encode":
        return { result: encodeURIComponent(input), error: "" };
      case "url-decode":
        return { result: decodeURIComponent(input), error: "" };
    }
  } catch {
    return { result: "", error: "转换失败：输入格式不正确" };
  }
}

export function Base64CodecModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const embedded = surfaceVariant === "embedded";
  const [mode, setMode] = useState<CodecMode>("base64-encode");
  const [input, setInput] = useState("");
  const [copyNotice, setCopyNotice] = useState("");

  const { result, error } = convert(input, mode);

  const handleCopy = useCallback(async () => {
    if (!result) return;
    if (await copyTextToClipboard(result)) {
      setCopyNotice("已复制");
    } else {
      setCopyNotice("复制失败");
    }
    window.setTimeout(() => setCopyNotice(""), 1500);
  }, [result]);

  return (
    <MiscModuleSurface module={module} embedded={embedded} icon={<Binary className="h-4 w-4" />} tone="cyan">
      <div className="flex flex-wrap gap-1.5">
        {modes.map((m) => (
          <button
            key={m.value}
            className={`meow-diffuse-chip px-2.5 py-1 text-[11px] ${mode === m.value ? "meow-diffuse-chip-active" : ""}`}
            onClick={() => setMode(m.value)}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-1">
          <label className="text-[11px] font-medium text-slate-500">输入</label>
          <Textarea
            className="font-mono text-xs"
            rows={6}
            placeholder="在此输入内容..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <label className="text-[11px] font-medium text-slate-500">输出</label>
          <Textarea
            className="font-mono text-xs"
            rows={6}
            readOnly
            value={error || result}
          />
        </div>
      </div>

      {error && <p className="text-[11px] text-red-600">{error}</p>}

      <div className="flex items-center gap-2">
        <button className="meow-control px-3 py-1.5 text-xs" onClick={handleCopy} disabled={!result}>
          复制输出
        </button>
        {copyNotice && <span className="text-[11px] text-emerald-600">{copyNotice}</span>}
      </div>
    </MiscModuleSurface>
  );
}
