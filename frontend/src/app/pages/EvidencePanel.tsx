import { EvidencePanelLayout } from "./EvidencePanelLayout";
import { useEvidencePanelState } from "./useEvidencePanelState";

export default function EvidencePanel() {
  return <EvidencePanelLayout {...useEvidencePanelState()} />;
}
