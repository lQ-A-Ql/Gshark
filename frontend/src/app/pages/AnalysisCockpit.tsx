import { CaptureMissionControl } from "../components/CaptureMissionControl";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { useSentinel } from "../state/SentinelContext";

export default function AnalysisCockpit() {
  const { fileMeta } = useSentinel();

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  return (
    <div className="flex h-full flex-col overflow-auto bg-background">
      <CaptureMissionControl />
    </div>
  );
}
