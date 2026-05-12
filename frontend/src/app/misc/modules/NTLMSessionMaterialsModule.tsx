import { KeyRound } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { NTLMSessionMaterial } from "../../core/types";
import { backendClients } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { exportStructuredResult, type MiscExportFormat } from "../exportResult";
import { copyTextToClipboard } from "../../utils/browserFile";
import { NTLMSessionMaterialDetails } from "./NTLMSessionMaterialDetails";
import { NTLMSessionMaterialList } from "./NTLMSessionMaterialList";
import { NTLMSessionMaterialsToolbar, type NTLMSessionProtocolFilter } from "./NTLMSessionMaterialsToolbar";
import {
  countCompleteNTLMSessionMaterials,
  filterNTLMSessionMaterials,
  renderNTLMSessionMaterialsText,
  renderNTLMSessionMaterialText,
  selectNTLMSessionMaterial,
} from "./NTLMSessionMaterialsUtils";

export function NTLMSessionMaterialsModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [materials, setMaterials] = useState<NTLMSessionMaterial[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<NTLMSessionProtocolFilter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedFrame, setSelectedFrame] = useState("");
  const [copyNotice, setCopyNotice] = useState("");
  const embedded = surfaceVariant === "embedded";

  async function loadMaterials() {
    if (!hasCapture) {
      setMaterials([]);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const rows = await backendClients.securityMaterial.listNTLMSessionMaterials();
      setMaterials(rows);
      setSelectedFrame((current) =>
        current && rows.some((item) => item.frameNumber === current) ? current : (rows[0]?.frameNumber ?? ""),
      );
    } catch (err) {
      setMaterials([]);
      setSelectedFrame("");
      setError(err instanceof Error ? err.message : "加载 NTLM 会话材料失败");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let disposed = false;
    if (!hasCapture) {
      setMaterials([]);
      setSelectedFrame("");
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    void backendClients.securityMaterial
      .listNTLMSessionMaterials()
      .then((rows) => {
        if (disposed) return;
        setMaterials(rows);
        setSelectedFrame(rows[0]?.frameNumber ?? "");
      })
      .catch((err) => {
        if (disposed) return;
        setMaterials([]);
        setSelectedFrame("");
        setError(err instanceof Error ? err.message : "加载 NTLM 会话材料失败");
      })
      .finally(() => {
        if (!disposed) {
          setLoading(false);
        }
      });
    return () => {
      disposed = true;
    };
  }, [hasCapture, fileMeta.path]);

  const filtered = useMemo(() => {
    return filterNTLMSessionMaterials(materials, protocolFilter, query);
  }, [materials, protocolFilter, query]);

  const selected = useMemo(() => selectNTLMSessionMaterial(filtered, selectedFrame), [filtered, selectedFrame]);

  const completeCount = useMemo(() => countCompleteNTLMSessionMaterials(materials), [materials]);

  async function copySelectedMaterial() {
    if (!selected) return;
    const text = renderNTLMSessionMaterialText(selected);
    if (await copyTextToClipboard(text)) {
      setCopyNotice(`已复制帧 #${selected.frameNumber} 的 NTLM 材料`);
    } else {
      setCopyNotice("复制失败");
    }
    window.setTimeout(() => setCopyNotice(""), 1800);
  }

  function exportMaterials(format: MiscExportFormat) {
    const rows = filtered;
    exportStructuredResult({
      filenameBase: "ntlm-session-materials",
      format,
      payload: rows,
      renderText: renderNTLMSessionMaterialsText,
    });
  }

  return (
    <Card
      className={
        embedded
          ? "min-w-0 h-fit border-0 bg-transparent shadow-none"
          : "min-w-0 h-fit overflow-hidden border-slate-200 bg-white shadow-sm"
      }
    >
      <CardHeader className={embedded ? "hidden" : "gap-2 border-b border-slate-100 bg-slate-50/70 pb-5"}>
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-100 text-violet-600">
            <KeyRound className="h-4 w-4" />
          </div>
          <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent className={embedded ? "space-y-5 px-0 pt-0" : "space-y-5 pt-6"}>
        <NTLMSessionMaterialsToolbar
          captureName={fileMeta.name}
          completeCount={completeCount}
          error={error}
          filteredCount={filtered.length}
          hasCapture={hasCapture}
          loading={loading}
          materialCount={materials.length}
          onProtocolFilterChange={setProtocolFilter}
          onQueryChange={setQuery}
          onRefresh={() => void loadMaterials()}
          protocolDomain={module.protocolDomain}
          protocolFilter={protocolFilter}
          query={query}
        />

        <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.95fr)_minmax(0,1.05fr)]">
          <NTLMSessionMaterialList
            filtered={filtered}
            hasCapture={hasCapture}
            onSelectFrame={setSelectedFrame}
            selected={selected}
          />
          <NTLMSessionMaterialDetails
            copyNotice={copyNotice}
            filtered={filtered}
            onCopySelected={copySelectedMaterial}
            onExport={exportMaterials}
            selected={selected}
          />
        </div>
      </CardContent>
    </Card>
  );
}
