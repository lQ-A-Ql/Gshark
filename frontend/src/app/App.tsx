import { RouterProvider } from "react-router";
import { RefreshCw } from "lucide-react";
import { router } from "./routes";
import { SentinelProvider, useSentinel } from "./state/SentinelContext";
import { useEffect, useState } from "react";
import { toolRuntimeProbeStateText, toolRuntimeProbeTransportText } from "./state/toolRuntimeProbeState";
import { cn } from "./components/ui/utils";

export function StartupGate() {
  const {
    backendConnected,
    backendStatus,
    tsharkStatus,
    isTSharkChecking,
    toolRuntimeCheckDegraded,
    setTSharkPath,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    refreshToolRuntimeSnapshot,
    toolRuntimeProbeState,
    toolRuntimeProbeTransport,
    lastToolRuntimeProbeError,
  } = useSentinel();
  const [enterMain, setEnterMain] = useState(false);
  const [pathInput, setPathInput] = useState("");
  const [savingPath, setSavingPath] = useState(false);
  const [pathNotice, setPathNotice] = useState("");
  const [probeNotice, setProbeNotice] = useState("");

  useEffect(() => {
    setPathInput(tsharkStatus.customPath || "");
  }, [tsharkStatus.customPath]);

  useEffect(() => {
    if (!backendConnected) {
      setEnterMain(false);
      setPathNotice("");
      setProbeNotice("");
      return;
    }

    const timer = window.setTimeout(() => {
      setEnterMain(true);
    }, 300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [backendConnected]);

  const handleSavePath = async (nextPath = pathInput) => {
    setSavingPath(true);
    setPathNotice("");
    try {
      const candidate = nextPath.trim();
      await setTSharkPath(candidate);
      setPathNotice(candidate ? "已保存 tshark 路径。" : "已清除自定义 tshark 路径。");
    } catch (error) {
      setPathNotice(error instanceof Error ? error.message : "tshark 路径保存失败。");
    } finally {
      setSavingPath(false);
    }
  };
  const handleProbeTools = async () => {
    setProbeNotice("");
    try {
      const snapshot = await refreshToolRuntimeSnapshot();
      setProbeNotice(snapshot ? "已重新探测工具状态。" : "后端未连接，暂时无法探测工具。");
    } catch (error) {
      setProbeNotice(lastToolRuntimeProbeError || (error instanceof Error ? error.message : "工具状态探测失败。"));
    }
  };
  const tsharkDegraded = Boolean(
    tsharkStatus.available &&
    (tsharkStatus.capabilityCheckDegraded || (tsharkStatus.missingOptionalFields?.length ?? 0) > 0),
  );
  const speech = toolRuntimeSnapshot?.speech;
  const speechStatusText = !toolRuntimeSnapshot
    ? toolRuntimeProbeStateText(toolRuntimeProbeState)
    : speech?.available
      ? "可用"
      : speech?.pythonAvailable
        ? speech.modelAvailable
          ? "部分就绪"
          : "模型缺失"
        : "未就绪";

  if (!enterMain) {
    return (
      <div className="gshark-page-bg gshark-glass-shell flex h-screen w-screen items-center justify-center overflow-hidden px-6 text-slate-900">
        <div className="gshark-tile gshark-workbench-panel gshark-forensic-scan w-full max-w-[600px] overflow-hidden">
          <div className="gshark-tile-header px-5 py-4">
            <div className="text-[11px] font-semibold tracking-[0.24em] text-blue-600">GSHARK SENTINEL</div>
            <h1 className="mt-2 text-2xl font-semibold text-slate-950">启动中</h1>
            <p className="mt-1 text-sm leading-6 text-slate-600">正在拉起后端服务并初始化前端界面。</p>
          </div>

          <div className="space-y-3 px-5 py-4">
            <div className="gshark-soft-fill space-y-3 px-3.5 py-3">
              <StartupStatusLine
                tone={backendConnected ? "emerald" : "amber"}
                pulse={!backendConnected}
                label="后端服务"
                value={backendConnected ? "已连接" : "启动中"}
              />
              <StartupStatusLine
                tone={
                  !backendConnected || isTSharkChecking
                    ? "slate"
                    : tsharkStatus.available
                      ? tsharkDegraded
                        ? "amber"
                        : "emerald"
                      : "rose"
                }
                pulse={!backendConnected || isTSharkChecking}
                label="tshark"
                value={
                  !backendConnected || isTSharkChecking
                    ? "检测中"
                    : tsharkStatus.available
                      ? tsharkDegraded
                        ? "可用，部分分析降级"
                        : "可用"
                      : toolRuntimeProbeState === "failed"
                        ? "探测失败"
                        : toolRuntimeCheckDegraded
                          ? "稍后重试"
                          : "不可用"
                }
              />
              <div className="grid grid-cols-2 gap-2 text-xs text-slate-600">
                <ToolRuntimeTile
                  label="FFmpeg"
                  value={
                    toolRuntimeSnapshot
                      ? toolRuntimeSnapshot.ffmpeg.available
                        ? "可用"
                        : "未就绪"
                      : toolRuntimeProbeStateText(toolRuntimeProbeState)
                  }
                />
                <ToolRuntimeTile label="Speech" value={speechStatusText} />
              </div>
            </div>
            <div className="gshark-diffuse-chip px-3 py-2 text-xs break-all text-slate-500">
              {backendStatus || "等待状态..."}
            </div>
            {!toolRuntimeSnapshot && backendConnected && (
              <div
                className={cn(
                  "gshark-soft-fill px-3 py-2 text-xs break-all",
                  toolRuntimeProbeState === "failed" ? "text-rose-600" : "text-slate-500",
                )}
              >
                {toolRuntimeProbeStateText(toolRuntimeProbeState)} ·{" "}
                {toolRuntimeProbeTransportText(toolRuntimeProbeTransport)}
                {lastToolRuntimeProbeError ? `：${lastToolRuntimeProbeError}` : ""}
              </div>
            )}
            {backendConnected && !isTSharkChecking && (
              <div
                className={cn(
                  "gshark-soft-fill px-3 py-2 text-xs break-all",
                  tsharkStatus.available ? (tsharkDegraded ? "text-amber-700" : "text-emerald-600") : "text-rose-600",
                )}
              >
                {tsharkStatus.available
                  ? `${tsharkDegraded ? "部分分析降级" : "已检测到"}: ${tsharkStatus.path || "tshark"}`
                  : tsharkStatus.message ||
                    (toolRuntimeCheckDegraded
                      ? "检测暂时未完成，可进入主界面后刷新状态"
                      : "未检测到 TShark，可在设置中配置")}
              </div>
            )}
            {tsharkDegraded && (tsharkStatus.missingOptionalFields?.length ?? 0) > 0 && (
              <div className="gshark-soft-fill px-3 py-2 text-xs break-all text-amber-700">
                缺少可选字段：{tsharkStatus.missingOptionalFields?.join(", ")}
              </div>
            )}
            {backendConnected && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => void handleProbeTools()}
                  disabled={isToolRuntimeLoading || toolRuntimeProbeState === "probing_full"}
                  className="gshark-control inline-flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-700 transition hover:text-cyan-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${isToolRuntimeLoading || toolRuntimeProbeState === "probing_full" ? "animate-spin" : ""}`}
                  />
                  重新探测工具
                </button>
                {probeNotice && <span className="text-xs text-slate-500">{probeNotice}</span>}
              </div>
            )}
          </div>

          {backendConnected && !isTSharkChecking && !tsharkStatus.available && !toolRuntimeCheckDegraded && (
            <div className="gshark-soft-fill gshark-risk-accent mx-5 mb-4 px-4 py-3">
              <div className="text-sm font-medium text-amber-800">未检测到 TShark，可在设置中配置</div>
              <p className="mt-1 text-xs text-amber-700">
                可以直接填写 tshark.exe 的绝对路径，或者填写 Wireshark 安装目录。
              </p>
              <div className="mt-3 flex gap-2">
                <input
                  value={pathInput}
                  onChange={(event) => setPathInput(event.target.value)}
                  placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
                  className="gshark-field flex-1 px-3 py-2 text-xs text-slate-900 outline-none"
                />
                <button
                  onClick={() => void handleSavePath()}
                  disabled={savingPath}
                  className="gshark-control-primary px-3 py-2 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {savingPath ? "保存中" : "保存路径"}
                </button>
              </div>
              {tsharkStatus.customPath && (
                <button
                  onClick={() => {
                    setPathInput("");
                    void handleSavePath("");
                  }}
                  disabled={savingPath}
                  className="gshark-control mt-2 px-3 py-1.5 text-xs text-slate-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  清除自定义路径
                </button>
              )}
              {pathNotice && <div className="mt-2 text-xs text-slate-600">{pathNotice}</div>}
            </div>
          )}

          <div className="mx-5 mb-5 h-1.5 overflow-hidden bg-slate-200/45">
            <div
              className={`h-full bg-gradient-to-r from-sky-500 to-blue-600 transition-all duration-500 ${backendConnected ? "w-full" : "w-2/3 animate-pulse"}`}
            />
          </div>
        </div>
      </div>
    );
  }

  return <RouterProvider router={router} />;
}

export default function App() {
  useEffect(() => {
    if (import.meta.env.DEV) return;

    const onContextMenu = (event: MouseEvent) => {
      event.preventDefault();
    };

    const onKeyDown = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      const disableDevtools =
        key === "f12" ||
        (event.ctrlKey && event.shiftKey && (key === "i" || key === "j" || key === "c")) ||
        (event.ctrlKey && key === "u");
      if (disableDevtools) {
        event.preventDefault();
      }
    };

    window.addEventListener("contextmenu", onContextMenu);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("contextmenu", onContextMenu);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  return (
    <SentinelProvider>
      <StartupGate />
    </SentinelProvider>
  );
}

function StartupStatusLine({
  label,
  value,
  tone,
  pulse = false,
}: {
  label: string;
  value: string;
  tone: "slate" | "emerald" | "amber" | "rose";
  pulse?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className={cn("gshark-status-dot", statusToneClassName[tone], pulse && "animate-pulse")} />
      <span>
        {label}：{value}
      </span>
    </div>
  );
}

function ToolRuntimeTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="gshark-diffuse-chip px-3 py-2">
      {label}：{value}
    </div>
  );
}

const statusToneClassName = {
  slate: "text-slate-400",
  emerald: "text-emerald-500",
  amber: "text-amber-500",
  rose: "text-rose-500",
};
