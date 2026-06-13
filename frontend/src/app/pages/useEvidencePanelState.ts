import { useEffect, useMemo, useState } from "react";
import type { EvidenceSeverity } from "../core/evidenceTypes";
import type { EvidenceFacetState } from "../features/evidence/evidencePanelRules";
import { useEvidence } from "../features/evidence/useEvidence";
import { useEvidencePanelModel } from "../features/evidence/useEvidencePanelModel";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";

function createEmptyFacets(): EvidenceFacetState {
  return {
    sourceTypes: [],
    features: [],
    entities: [],
    confidenceLabels: [],
  };
}

export function useEvidencePanelState() {
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { totalPackets } = usePacket();
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<EvidenceSeverity | "all">("all");
  const [facets, setFacets] = useState<EvidenceFacetState>(createEmptyFacets);
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  const { evidence, loading, error, refreshEvidence } = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: selectedModules.length > 0 ? selectedModules : undefined,
  });

  const model = useEvidencePanelModel(evidence, query, severityFilter, facets, selectedRecordId);

  useEffect(() => {
    if (selectedRecordId !== model.effectiveSelectedRecordId) {
      setSelectedRecordId(model.effectiveSelectedRecordId);
    }
  }, [model.effectiveSelectedRecordId, selectedRecordId]);

  const toggleModule = (module: string) =>
    setSelectedModules((prev) => (prev.includes(module) ? prev.filter((item) => item !== module) : [...prev, module]));

  const toggleFacet = (group: keyof EvidenceFacetState, value: string) => {
    setFacets((prev) => ({
      ...prev,
      [group]: prev[group].includes(value) ? prev[group].filter((item) => item !== value) : [...prev[group], value],
    }));
  };

  return {
    ...model,
    evidence,
    error,
    facets,
    heroTags: useMemo(() => ["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"], []),
    loading,
    query,
    severityFilter,
    selectedModules,
    refreshEvidence,
    resetFacets: () => setFacets(createEmptyFacets()),
    setQuery,
    setSelectedRecordId,
    setSeverityFilter,
    toggleFacet,
    toggleModule,
  };
}

export type EvidencePanelState = ReturnType<typeof useEvidencePanelState>;
