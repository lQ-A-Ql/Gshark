import { useEffect, useMemo, useState } from "react";
import type { StreamPayloadInspection } from "../core/types";
import { backendClients } from "../integrations/backendClients";
import { isAbortError } from "./StreamDecoderWorkbenchUtils";

export function useStreamPayloadInspection({
  payload,
  preparedPayload,
  inspectRevision,
}: {
  payload: string;
  preparedPayload: string;
  inspectRevision?: number | string;
}) {
  const [inspection, setInspection] = useState<StreamPayloadInspection | null>(null);
  const [inspectionLoading, setInspectionLoading] = useState(false);
  const [inspectionError, setInspectionError] = useState("");
  const [selectedCandidateId, setSelectedCandidateId] = useState("");

  const selectedCandidate = useMemo(
    () => inspection?.candidates.find((item) => item.id === selectedCandidateId) ?? inspection?.candidates[0] ?? null,
    [inspection, selectedCandidateId],
  );

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    if (!preparedPayload.trim()) {
      setInspection(null);
      setInspectionError("");
      setInspectionLoading(false);
      setSelectedCandidateId("");
      return;
    }
    setInspectionLoading(true);
    setInspectionError("");
    void backendClients.stream
      .inspectStreamPayload(payload, controller.signal)
      .then((next) => {
        if (cancelled) return;
        setInspection(next);
        const suggested =
          next.suggestedCandidateId && next.candidates.some((item) => item.id === next.suggestedCandidateId)
            ? next.suggestedCandidateId
            : (next.candidates[0]?.id ?? "");
        setSelectedCandidateId(suggested);
      })
      .catch((error) => {
        if (cancelled) return;
        if (isAbortError(error)) return;
        setInspection(null);
        setSelectedCandidateId("");
        setInspectionError(error instanceof Error ? error.message : "payload 候选提取失败");
      })
      .finally(() => {
        if (!cancelled) {
          setInspectionLoading(false);
        }
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [payload, preparedPayload, inspectRevision]);

  return {
    inspection,
    inspectionError,
    inspectionLoading,
    selectedCandidate,
    setSelectedCandidateId,
  };
}
