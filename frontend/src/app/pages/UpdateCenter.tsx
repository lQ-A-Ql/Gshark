import { useEffect, useState } from "react";
import { Sparkles } from "lucide-react";
import type { AppUpdateStatus } from "../core/types";
import { backendClients } from "../integrations/wailsBridge";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  UpdateDiagnosticsPanel,
  UpdateReleaseNotesPanel,
  UpdateStatusPanel,
  UpdateStepsPanel,
} from "../features/update/UpdateCenterPanels";

export default function UpdateCenter() {
  const [status, setStatus] = useState<AppUpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState("");
  const [installProgress, setInstallProgress] = useState(0);

  const refreshStatus = async () => {
    setLoading(true);
    setError("");
    try {
      const next = await backendClients.runtime.checkAppUpdate();
      setStatus(next);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "检查更新失败");
    } finally {
      setLoading(false);
    }
  };

  const installUpdate = async () => {
    setInstalling(true);
    setError("");
    setInstallProgress(12);
    try {
      await backendClients.runtime.installAppUpdate();
      setInstallProgress(100);
    } catch (nextError) {
      setInstalling(false);
      setInstallProgress(0);
      setError(nextError instanceof Error ? nextError.message : "启动更新失败");
      await refreshStatus();
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    if (!installing) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      setInstallProgress((prev) => {
        if (prev >= 92) {
          return prev;
        }
        return Math.min(92, prev + 6);
      });
    }, 420);
    return () => window.clearInterval(timer);
  }, [installing]);

  const notes = status?.releaseNotes?.trim() || "该版本没有附带 Release 说明。";

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
