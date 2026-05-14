import { Sparkles } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  UpdateDiagnosticsPanel,
  UpdateReleaseNotesPanel,
  UpdateStatusPanel,
  UpdateStepsPanel,
} from "../features/update/UpdateCenterPanels";
import { useUpdateCenter } from "../features/update/useUpdateCenter";

export default function UpdateCenter() {
  const { status, loading, installing, error, installProgress, notes, refreshStatus, installUpdate } =
    useUpdateCenter();

  return (
    <PageShell>
      <AnalysisHero
        icon={<Sparkles className="h-5 w-5" />}
        title="更新中心"
        subtitle="UPDATE CENTER"
        description="统一查看 version.json 自动检测结果、安装资产、Release 说明和替换流程，保证更新页与其他专题页保持同一标题区和布局节奏。"
        tags={["version.json", "自动更新", "Release", "桌面程序"]}
        tagsLabel="更新域"
        theme="blue"
        onRefresh={() => void refreshStatus()}
        refreshLabel="重新检查"
      />

      <UpdateStatusPanel
        status={status}
        loading={loading}
        installing={installing}
        installProgress={installProgress}
        error={error}
        onRefresh={() => void refreshStatus()}
        onInstall={() => void installUpdate()}
      />

      <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <UpdateReleaseNotesPanel notes={notes} />
        <UpdateDiagnosticsPanel status={status} error={error} />
        <UpdateStepsPanel />
      </div>
    </PageShell>
  );
}
