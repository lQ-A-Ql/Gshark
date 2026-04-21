import { Radar } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureMissionControl } from "../components/CaptureMissionControl";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { PageShell } from "../components/PageShell";
import { useSentinel } from "../state/SentinelContext";

export default function AnalysisCockpit() {
  const { fileMeta } = useSentinel();

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
      <AnalysisHero
        icon={<Radar className="h-5 w-5" />}
        title="分析驾驶舱"
        subtitle="ANALYSIS COCKPIT"
        description="围绕当前抓包生成统一的首屏态势、推荐入口、优先处理命中与 payload 快速解码，作为所有专题分析的起点。"
        tags={["总览", "推荐入口", "命中优先级", "Payload 解码"]}
        tagsLabel="驾驶舱域"
        theme="blue"
      />
      <CaptureMissionControl />
    </PageShell>
  );
}
