import { RouterProvider } from "react-router";
import { RefreshCw } from "lucide-react";
import { router } from "./routes";
import { SentinelProvider, useSentinel } from "./state/SentinelContext";
import { useEffect, useState } from "react";

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
      setProbeNotice(error instanceof Error ? error.message : "工具状态探测失败。");
    }
  };
  const tsharkDegraded = Boolean(
    tsharkStatus.available &&
    (tsharkStatus.capabilityCheckDegraded || (tsharkStatus.missingOptionalFields?.length ?? 0) > 0),
  );
  const speech = toolRuntimeSnapshot?.speech;
  const speechStatusText = !toolRuntimeSnapshot
    ? "未检测"
    : speech?.available
      ? "可用"
      : speech?.pythonAvailable
        ? speech.modelAvailable
          ? "部分就绪"
          : "模型缺失"
        : "未就绪";

  if (!enterMain) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-slate-100 text-slate-900">
        <div className="w-[560px] rounded-2xl border border-slate-200 bg-white p-8 shadow-xl">
          <div className="mb-3 text-xs tracking-[0.24em] text-blue-600">GSHARK SENTINEL</div>
          <h1 className="text-3xl font-semibold text-slate-900">启动中</h1>
          <p className="mt-2 text-sm text-slate-600">正在拉起后端服务并初始化前端界面。</p>

          <div className="mt-6 space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center gap-3 text-sm">
              <span
                className={`inline-block h-2.5 w-2.5 rounded-full ${backendConnected ? "bg-emerald-500" : "bg-amber-500 animate-pulse"}`}
              />
              <span>后端服务：{backendConnected ? "已连接" : "启动中"}</span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <span
                className={`inline-block h-2.5 w-2.5 rounded-full ${!backendConnected || isTSharkChecking ? "bg-slate-400 animate-pulse" : tsharkStatus.available ? (tsharkDegraded ? "bg-amber-500" : "bg-emerald-500") : "bg-rose-500"}`}
              />
              <span>
                tshark：
                {!backendConnected || isTSharkChecking
                  ? "检测中"
                  : tsharkStatus.available
                    ? tsharkDegraded
                      ? "可用，部分分析降级"
                      : "可用"
                    : toolRuntimeCheckDegraded
                      ? "稍后重试"
                      : "不可用"}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs text-slate-600">
              <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
                FFmpeg：{toolRuntimeSnapshot ? (toolRuntimeSnapshot.ffmpeg.available ? "可用" : "未就绪") : "未检测"}
              </div>
              <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">Speech：{speechStatusText}</div>
            </div>
            <div className="text-xs text-slate-500 break-all">{backendStatus || "等待状态..."}</div>
            {backendConnected && !isTSharkChecking && (
              <div
                className={`text-xs break-all ${tsharkStatus.available ? (tsharkDegraded ? "text-amber-700" : "text-emerald-600") : "text-rose-600"}`}
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
              <div className="text-xs text-amber-700 break-all">
                缺少可选字段：{tsharkStatus.missingOptionalFields?.join(", ")}
              </div>
            )}
            {backendConnected && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => void handleProbeTools()}
                  disabled={isToolRuntimeLoading}
                  className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${isToolRuntimeLoading ? "animate-spin" : ""}`} />
                  重新探测工具
                </button>
                {probeNotice && <span className="text-xs text-slate-500">{probeNotice}</span>}
              </div>
            )}
          </div>

          {backendConnected && !isTSharkChecking && !tsharkStatus.available && !toolRuntimeCheckDegraded && (
            <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50 p-4">
              <div className="text-sm font-medium text-amber-800">未检测到 TShark，可在设置中配置</div>
              <p className="mt-1 text-xs text-amber-700">
                可以直接填写 tshark.exe 的绝对路径，或者填写 Wireshark 安装目录。
              </p>
              <div className="mt-3 flex gap-2">
                <input
                  value={pathInput}
                  onChange={(event) => setPathInput(event.target.value)}
                  placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
                  className="flex-1 rounded-md border border-amber-200 bg-white px-3 py-2 text-xs text-slate-900 outline-none focus:border-blue-500"
                />
                <button
                  onClick={() => void handleSavePath()}
                  disabled={savingPath}
                  className="rounded-md border border-blue-200 bg-blue-600 px-3 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
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
                  className="mt-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  清除自定义路径
                </button>
              )}
              {pathNotice && <div className="mt-2 text-xs text-slate-600">{pathNotice}</div>}
            </div>
          )}

          <div className="mt-5 h-1.5 w-full overflow-hidden rounded bg-slate-200">
            <div
              className={`h-full rounded bg-gradient-to-r from-sky-500 to-blue-600 transition-all duration-500 ${backendConnected ? "w-full" : "w-2/3 animate-pulse"}`}
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
