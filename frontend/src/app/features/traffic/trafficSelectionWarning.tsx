import { StatusHint } from "../../components/DesignSystem";
import { GLOBAL_SELECTION_WARNING } from "./trafficGraphPanelModel";

export function TrafficSelectionWarning({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <StatusHint tone="blue" className="mb-3 text-xs">
      {GLOBAL_SELECTION_WARNING}
    </StatusHint>
  );
}
