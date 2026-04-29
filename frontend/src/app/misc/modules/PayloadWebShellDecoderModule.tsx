import { Binary, ClipboardPaste, Eraser, Search } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import { StreamDecoderWorkbench } from "../../components/StreamDecoderWorkbench";
import type { MiscModuleRendererProps } from "../types";

const SAMPLE_PAYLOAD = "pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==";

export function PayloadWebShellDecoderModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const [draft, setDraft] = useState("");
  const [payload, setPayload] = useState("");
  const embedded = surfaceVariant === "embedded";

  function analyzePayload() {
    setPayload(draft);
  }

  function clearPayload() {
    setDraft("");
    setPayload("");
  }

  function useSamplePayload() {
    setDraft(SAMPLE_PAYLOAD);
    setPayload(SAMPLE_PAYLOAD);
  }

  return (
    <div className={embedded ? "space-y-4" : "space-y-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"}>
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-100 bg-slate-50/80 px-4 py-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Binary className="h-4 w-4 text-cyan-600" />
                {module.title}
              </div>
              <p className="mt-1 max-w-3xl text-[12px] leading-6 text-slate-500">
                手动粘贴 HTTP 报文、body、form 参数、multipart、Base64、Hex 或单个可疑参数值。非 Base64 家族解码会显示置信度与失败阶段，结果仅用于分析，不写回抓包。
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" onClick={useSamplePayload} className="h-8 gap-2 bg-white text-xs">
                <ClipboardPaste className="h-3.5 w-3.5" />
                示例
              </Button>
              <Button type="button" variant="outline" onClick={clearPayload} className="h-8 gap-2 bg-white text-xs">
                <Eraser className="h-3.5 w-3.5" />
                清空
              </Button>
              <Button type="button" onClick={analyzePayload} className="h-8 gap-2 bg-slate-900 text-xs text-white hover:bg-slate-800">
                <Search className="h-3.5 w-3.5" />
                识别候选
              </Button>
            </div>
          </div>
        </div>
        <div className="p-4">
          <textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder={"POST /shell.php HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npass=..."}
            className="min-h-[180px] w-full resize-y rounded-xl border border-slate-200 bg-slate-950 px-4 py-3 font-mono text-xs leading-6 text-slate-100 outline-none transition focus:border-cyan-300 focus:ring-4 focus:ring-cyan-100"
            spellCheck={false}
          />
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
            <span>当前输入 {draft.length.toLocaleString()} 字符，已提交分析 {payload.length.toLocaleString()} 字符。</span>
            <span className="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 font-semibold text-amber-700">实验性 webshell 解码，需人工复核</span>
          </div>
        </div>
      </div>

      <StreamDecoderWorkbench
        payload={payload}
        chunkLabel={payload ? "MISC 手动输入 payload" : "等待手动输入 payload"}
        tone="blue"
      />
    </div>
  );
}
