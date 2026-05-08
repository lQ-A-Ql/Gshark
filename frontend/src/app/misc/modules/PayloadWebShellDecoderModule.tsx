import { Binary, ClipboardPaste, Eraser, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "../../components/ui/button";
import { AnalysisBadge, AnalysisMiniStat } from "../../components/analysis/AnalysisPrimitives";
import { StreamDecoderWorkbench } from "../../components/StreamDecoderWorkbench";
import type { StreamPayloadSource } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { PayloadWebShellSourceList } from "./PayloadWebShellSourceList";

const SAMPLE_PAYLOAD = "pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==";

export function PayloadWebShellDecoderModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const [draft, setDraft] = useState("");
  const [payload, setPayload] = useState("");
  const [inspectRevision, setInspectRevision] = useState(0);
  const [inputHint, setInputHint] = useState("");
  const [sources, setSources] = useState<StreamPayloadSource[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(false);
  const [sourcesError, setSourcesError] = useState("");
  const [selectedSource, setSelectedSource] = useState<StreamPayloadSource | null>(null);
  const draftRef = useRef("");
  const embedded = surfaceVariant === "embedded";
  const { fileMeta } = useSentinel();

  useEffect(() => {
    if (!fileMeta.path) {
      setSources([]);
      setSourcesError("");
      setSourcesLoading(false);
      return;
    }
    const controller = new AbortController();
    setSourcesLoading(true);
    setSourcesError("");
    bridge
      .listStreamPayloadSources(controller.signal, 500)
      .then((rows) => {
        if (controller.signal.aborted) return;
        setSources(rows);
      })
      .catch((error) => {
        if (controller.signal.aborted) return;
        setSourcesError(error instanceof Error ? error.message : "加载可疑 URI 失败");
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setSourcesLoading(false);
        }
      });
    return () => controller.abort();
  }, [fileMeta.path]);

  function analyzePayload() {
    const nextPayload = draftRef.current;
    if (!nextPayload.trim()) {
      setInputHint("请输入 payload 后再识别候选。");
      return;
    }
    setInputHint("");
    setPayload(nextPayload);
    setInspectRevision((current) => current + 1);
  }

  function clearPayload() {
    draftRef.current = "";
    setDraft("");
    setPayload("");
    setInputHint("");
    setSelectedSource(null);
    setInspectRevision((current) => current + 1);
  }

  function useSamplePayload() {
    draftRef.current = SAMPLE_PAYLOAD;
    setDraft(SAMPLE_PAYLOAD);
    setPayload(SAMPLE_PAYLOAD);
    setInputHint("");
    setSelectedSource(null);
    setInspectRevision((current) => current + 1);
  }

  function usePayloadSource(source: StreamPayloadSource) {
    draftRef.current = source.payload;
    setDraft(source.payload);
    setPayload(source.payload);
    setSelectedSource(source);
    setInputHint("");
    setInspectRevision((current) => current + 1);
  }

  return (
    <div className={embedded ? "space-y-4" : "space-y-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"}>
      <div
        className={
          embedded
            ? "overflow-hidden rounded-2xl border border-slate-100 bg-slate-50/60"
            : "overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"
        }
      >
        <div
          className={
            embedded
              ? "border-b border-slate-100 bg-transparent px-4 py-3"
              : "border-b border-slate-100 bg-slate-50/80 px-4 py-3"
          }
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Binary className="h-4 w-4 text-cyan-600" />
                {embedded ? "手动 Payload 输入" : module.title}
              </div>
              <p className="mt-1 max-w-3xl text-[12px] leading-6 text-slate-500">
                手动粘贴 HTTP 报文、body、form 参数、multipart、Base64、Hex 或单个可疑参数值。非 Base64
                家族解码会显示置信度与失败阶段，结果仅用于分析，不写回抓包。
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {!module.requiresCapture ? <AnalysisBadge tone="emerald">无需抓包</AnalysisBadge> : null}
                {module.cancellable ? <AnalysisBadge tone="cyan">可取消</AnalysisBadge> : null}
                {module.supportsExport ? <AnalysisBadge tone="blue">支持导出</AnalysisBadge> : null}
                <AnalysisBadge tone="amber">实验性</AnalysisBadge>
              </div>
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
              <Button
                type="button"
                onClick={analyzePayload}
                className="h-8 gap-2 bg-cyan-600 text-xs text-white shadow-sm hover:bg-cyan-700"
              >
                <Search className="h-3.5 w-3.5" />
                识别候选
              </Button>
            </div>
          </div>
        </div>
        <div className="p-4">
          <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <AnalysisMiniStat title="HTTP 报文" value="Request / Response" tone="cyan" />
            <AnalysisMiniStat title="参数来源" value="Query / Form / Multipart" tone="emerald" />
            <AnalysisMiniStat title="结构化输入" value="JSON / Body / 单参数" tone="blue" />
            <AnalysisMiniStat title="包裹编码" value="Base64url / Hex / URL 多轮" tone="amber" />
          </div>
          <PayloadWebShellSourceList
            hasCapture={Boolean(fileMeta.path)}
            loading={sourcesLoading}
            error={sourcesError}
            sources={sources}
            selectedSource={selectedSource}
            onSelect={usePayloadSource}
          />
          {selectedSource ? (
            <div className="mb-3 rounded-xl border border-cyan-100 bg-cyan-50/70 px-3 py-2 text-xs leading-5 text-cyan-900">
              当前输入来自 packet #{selectedSource.packetId}
              {selectedSource.streamId ? ` / stream ${selectedSource.streamId}` : ""} · {selectedSource.method}{" "}
              {selectedSource.host}
              {selectedSource.uri}
            </div>
          ) : null}
          <textarea
            value={draft}
            onChange={(event) => {
              draftRef.current = event.target.value;
              setDraft(event.target.value);
              if (inputHint) {
                setInputHint("");
              }
            }}
            placeholder={
              "POST /shell.php HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npass=..."
            }
            className="min-h-[180px] w-full resize-y rounded-xl border border-slate-200 bg-white/95 px-4 py-3 font-mono text-xs leading-6 text-slate-800 shadow-inner outline-none transition placeholder:text-slate-400 focus:border-cyan-300 focus:ring-4 focus:ring-cyan-100"
            spellCheck={false}
          />
          {inputHint ? (
            <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">
              {inputHint}
            </div>
          ) : null}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
            <span>
              当前输入 {draft.length.toLocaleString()} 字符，已提交分析 {payload.length.toLocaleString()} 字符。
            </span>
            <AnalysisBadge tone="amber" className="px-2.5 py-1">
              候选可疑与低置信结果需要人工确认
            </AnalysisBadge>
          </div>
        </div>
      </div>

      <StreamDecoderWorkbench
        payload={payload}
        inspectRevision={inspectRevision}
        chunkLabel={payload ? "MISC 手动输入 payload" : "等待手动输入 payload"}
        tone="blue"
        sourceHint={selectedSource ?? undefined}
      />
    </div>
  );
}
