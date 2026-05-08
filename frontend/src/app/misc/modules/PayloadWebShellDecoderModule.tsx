import { useEffect, useRef, useState } from "react";
import { StreamDecoderWorkbench } from "../../components/StreamDecoderWorkbench";
import type { StreamPayloadSource } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { PayloadWebShellInputPanel } from "./PayloadWebShellInputPanel";

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

  function updateDraft(value: string) {
    draftRef.current = value;
    setDraft(value);
    if (inputHint) {
      setInputHint("");
    }
  }

  return (
    <div className={embedded ? "space-y-4" : "space-y-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"}>
      <PayloadWebShellInputPanel
        module={module}
        embedded={embedded}
        draft={draft}
        payload={payload}
        inputHint={inputHint}
        hasCapture={Boolean(fileMeta.path)}
        sourcesLoading={sourcesLoading}
        sourcesError={sourcesError}
        sources={sources}
        selectedSource={selectedSource}
        onDraftChange={updateDraft}
        onSelectSource={usePayloadSource}
        onUseSample={useSamplePayload}
        onClear={clearPayload}
        onAnalyze={analyzePayload}
      />

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
