import { AlertTriangle, ArrowDownToLine, CheckCircle2, Github, LoaderCircle, RefreshCw } from "lucide-react";
import type { AppUpdateStatus } from "../../core/types";
import { LazyMarkdown } from "../../components/LazyMarkdown";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Progress } from "../../components/ui/progress";
import { formatBytes } from "../../state/SentinelContext";
import { releaseMarkdownComponents } from "./UpdateReleaseMarkdown";
import { formatReleaseTime } from "./updateCenterUtils";

interface UpdateStatusPanelProps {
  status: AppUpdateStatus | null;
  loading: boolean;
  installing: boolean;
  installProgress: number;
  error: string;
  onRefresh: () => void;
  onInstall: () => void;
}

export function UpdateStatusPanel({
  status,
  loading,
  installing,
  installProgress,
  error,
  onRefresh,
  onInstall,
}: UpdateStatusPanelProps) {
  const actionDisabled = loading || installing || !status?.hasUpdate || !status?.canInstall;

  return (
    <Card className="overflow-hidden border-blue-200 bg-gradient-to-br from-white via-blue-50 to-cyan-50 shadow-sm">
      <CardContent className="space-y-5 pt-6">
        <div className="grid gap-4 md:grid-cols-4">
          <StatusTile
            title="当前版本"
            value={status?.currentVersionDisplay || "读取中"}
            hint={status ? `来源: ${status.currentVersionSource || "unknown"}` : "正在读取本地版本信息"}
          />
          <StatusTile
            title="最新 Release"
            value={status?.latestTag || "等待检查"}
            hint={status?.latestPublishedAt ? formatReleaseTime(status.latestPublishedAt) : "尚未获取发布时间"}
          />
          <StatusTile
            title="更新资产"
            value={status?.selectedAsset?.name || "暂无匹配资产"}
            hint={status?.selectedAsset ? formatBytes(status.selectedAsset.sizeBytes) : "当前 Release 未匹配到安装包"}
          />
          <StatusTile
            title="本地 SHA-256"
            value={status?.localHash ? `${status.localHash.slice(0, 16)}…` : "计算中"}
            hint={
              status?.hashMismatch
                ? "⚠ 本地程序与 Release 资产大小不一致"
                : status?.localHash
                  ? "已完成本地程序哈希计算"
                  : "正在计算本地程序哈希"
            }
          />
        </div>

        {(loading || installing) && (
          <div className="rounded-xl border border-blue-100 bg-white/80 p-4 shadow-sm">
            <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-700">
              <LoaderCircle className="h-4 w-4 animate-spin text-blue-600" />
              {installing ? "正在下载并替换程序" : "正在检查 GitHub Release"}
            </div>
            <Progress value={installing ? installProgress : 28} className="h-2.5" />
            <p className="mt-3 text-xs leading-5 text-slate-500">
              {installing
                ? "更新包下载完成后，程序会自动退出、替换原文件并重新启动。"
                : "正在读取公开 version.json 更新清单。"}
            </p>
          </div>
        )}

        {error && <UpdateErrorNotice error={error} />}
        {status && !error && <UpdateStateNotice status={status} />}

        <div className="flex flex-wrap gap-3">
          <Button onClick={onRefresh} disabled={loading || installing}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            重新检查
          </Button>
          <Button onClick={onInstall} disabled={actionDisabled} variant="secondary">
            <ArrowDownToLine className="h-4 w-4" />
            下载并替换当前程序
          </Button>
          {status?.releaseUrl && (
            <Button variant="outline" asChild>
              <a href={status.releaseUrl} target="_blank" rel="noreferrer">
                <Github className="h-4 w-4" />
                查看 Release 页面
              </a>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export function UpdateReleaseNotesPanel({ notes }: { notes: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg font-semibold text-slate-900">Release 说明</CardTitle>
        <CardDescription>这里展示 GitHub 最新 Release 的正文内容，方便确认变更范围。</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="max-h-[420px] overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-4">
          <LazyMarkdown components={releaseMarkdownComponents}>{notes}</LazyMarkdown>
        </div>
      </CardContent>
    </Card>
  );
}

export function UpdateDiagnosticsPanel({ status, error }: { status: AppUpdateStatus | null; error: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg font-semibold text-slate-900">查询诊断</CardTitle>
        <CardDescription>用于确认更新中心到底访问了哪个仓库和接口，也方便区分代码问题与网络环境问题。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm text-slate-700">
        <DiagnosticRow label="目标仓库" value={status?.repo || "读取中"} />
        <DiagnosticRow label="检查方式" value={status?.authMode || "读取中"} />
        <DiagnosticRow label="更新清单" value={status?.apiUrl || "读取中"} />
        <DiagnosticRow label="最近检查" value={status?.checkedAt ? formatReleaseTime(status.checkedAt) : "尚未检查"} />
        <DiagnosticRow
          label="诊断结论"
          value={
            error
              ? "程序已进入错误分支；若更新清单地址可在浏览器打开，优先排查代理、证书或桌面运行环境差异。"
              : "当前检查走公开 version.json 清单，不依赖 GitHub API Token 或限流额度。"
          }
        />
      </CardContent>
    </Card>
  );
}

export function UpdateStepsPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg font-semibold text-slate-900">更新步骤</CardTitle>
        <CardDescription>当前流程只替换主程序本体，不会动你的本地抓包文件和分析记录。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <StepCard
          index="01"
          title="读取更新清单"
          description="访问公开 version.json，读取最新版本号、发布时间、Release 页面和安装资产。"
        />
        <StepCard
          index="02"
          title="下载发布包"
          description="选择与当前系统匹配的更新资产并下载到临时目录，避免污染程序目录。"
        />
        <StepCard
          index="03"
          title="替换原始文件"
          description="程序退出后由外部脚本执行覆盖替换，规避 Windows 正在运行的 exe 无法直接覆盖的问题。"
        />
        <StepCard index="04" title="自动重启" description="替换成功后会自动拉起新版本，无需手动重新打开。" />
      </CardContent>
    </Card>
  );
}

function UpdateErrorNotice({ error }: { error: string }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0">
        <div className="font-medium">更新检查失败</div>
        <div className="mt-1 break-words text-rose-600">{error}</div>
      </div>
    </div>
  );
}

function UpdateStateNotice({ status }: { status: AppUpdateStatus }) {
  return (
    <div
      className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${
        status.hasUpdate
          ? "border-amber-200 bg-amber-50 text-amber-700"
          : "border-emerald-200 bg-emerald-50 text-emerald-700"
      }`}
    >
      {status.hasUpdate ? (
        <ArrowDownToLine className="mt-0.5 h-4 w-4 shrink-0" />
      ) : (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
      )}
      <div className="min-w-0">
        <div className="font-medium">{status.message}</div>
        <div className="mt-1 break-all text-xs opacity-80">当前程序: {status.currentExecutable || "未知路径"}</div>
      </div>
    </div>
  );
}

function StatusTile({ title, value, hint }: { title: string; value: string; hint: string }) {
  return (
    <div className="rounded-2xl border border-white/70 bg-white/80 p-4 shadow-sm backdrop-blur">
      <div className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">{title}</div>
      <div className="mt-3 break-all text-lg font-semibold text-slate-900">{value}</div>
      <div className="mt-2 text-xs leading-5 text-slate-500">{hint}</div>
    </div>
  );
}

function StepCard({ index, title, description }: { index: string; title: string; description: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center gap-3">
        <div className="rounded-full bg-blue-600 px-2.5 py-1 text-xs font-semibold tracking-[0.18em] text-white">
          {index}
        </div>
        <div className="text-sm font-semibold text-slate-900">{title}</div>
      </div>
      <div className="mt-3 text-sm leading-6 text-slate-600">{description}</div>
    </div>
  );
}

function DiagnosticRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className="mt-2 break-all font-mono text-[13px] leading-6 text-slate-800">{value}</div>
    </div>
  );
}
