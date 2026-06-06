import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useEvidence } from "../features/evidence/useEvidence";
import type { TrafficGraphSection } from "../features/traffic/TrafficGraphPanels";
import type { TrafficTimelineRangeSelection, TrafficTimelineSelection } from "../features/traffic/trafficTimeline";
import { useTrafficGraph } from "../features/traffic/useTrafficGraph";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { useFilter } from "../state/contexts/FilterContext";
import { usePacket } from "../state/contexts/PacketContext";

export function useTrafficGraphPageState() {
  const [selectedSection, setSelectedSection] = useState<TrafficGraphSection>("overview");
  const [timelineSelection, setTimelineSelection] = useState<TrafficTimelineSelection>({
    hoveredLabel: null,
    lockedLabel: null,
    selectedRange: null,
  });
  const navigate = useNavigate();
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { setDisplayFilter, applyFilter } = useFilter();
  const { totalPackets } = usePacket();
  const { stats, loading, error, refreshStats } = useTrafficGraph({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });
  const evidenceState = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: ["hunting"],
  });

  const jumpWithFilter = useCallback((filter: string) => {
    if (!filter.trim()) return;
    setDisplayFilter(filter);
    applyFilter(filter);
    navigate("/");
  }, [applyFilter, navigate, setDisplayFilter]);

  return {
    error,
    evidenceError: evidenceState.error || null,
    evidenceLoading: evidenceState.loading,
    evidenceRecords: evidenceState.evidence,
    loading,
    refreshStats,
    selectedSection,
    stats,
    timelineSelection,
    trafficTags: useMemo(() => ["全局视图", "忽略过滤器", "协议分布", "会话热点"], []),
    jumpWithFilter,
    setSelectedSection,
    clearTimelineSelection: useCallback(() => setTimelineSelection({ hoveredLabel: null, lockedLabel: null, selectedRange: null }), []),
    setTimelineHoverLabel: useCallback((label: string | null) => setTimelineSelection((current) => ({ ...current, hoveredLabel: label })), []),
    setTimelineLockedLabel: useCallback((label: string | null) => setTimelineSelection((current) => ({ ...current, lockedLabel: label })), []),
    setTimelineRange: useCallback((range: TrafficTimelineRangeSelection | null) => setTimelineSelection((current) => ({ ...current, selectedRange: range })), []),
  };
}

export type TrafficGraphPageState = ReturnType<typeof useTrafficGraphPageState>;
