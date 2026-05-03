import { RouterProvider } from 'react-router';
import { router } from './routes';
import { SentinelProvider, useSentinel } from './state/SentinelContext';
import { useEffect, useState } from 'react';

function StartupGate() {
  const {
    backendConnected,
    backendStatus,
    tsharkStatus,
    isTSharkChecking,
    toolRuntimeCheckDegraded,
    setTSharkPath,
  } = useSentinel();
  const [enterMain, setEnterMain] = useState(false);
  const [pathInput, setPathInput] = useState('');
  const [savingPath, setSavingPath] = useState(false);
  const [pathNotice, setPathNotice] = useState('');

  useEffect(() => {
    setPathInput(tsharkStatus.customPath || '');
  }, [tsharkStatus.customPath]);

  useEffect(() => {
    if (!backendConnected) {
      setEnterMain(false);
      setPathNotice('');
      return;
    }

    if (isTSharkChecking || (!tsharkStatus.available && !toolRuntimeCheckDegraded)) {
      setEnterMain(false);
      return;
    }

    const timer = window.setTimeout(() => {
      setEnterMain(true);
    }, 300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [backendConnected, isTSharkChecking, toolRuntimeCheckDegraded, tsharkStatus.available]);

  const handleSavePath = async (nextPath = pathInput) => {
    setSavingPath(true);
    setPathNotice('');
    try {
      const candidate = nextPath.trim();
      await setTSharkPath(candidate);
      setPathNotice(candidate ? '已保存 tshark 路径。' : '已清除自定义 tshark 路径。');
    } catch (error) {
      setPathNotice(error instanceof Error ? error.message : 'tshark 路径保存失败。');
    } finally {
      setSavingPath(false);
    }
  };

  if (!enterMain) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-slate-100 text-slate-900">
        <div className="w-[560px] rounded-2xl border border-slate-200 bg-white p-8 shadow-xl">
          <div className="mb-3 text-xs tracking-[0.24em] text-blue-600">GSHARK SENTINEL</div>
          <h1 className="text-3xl font-semibold text-slate-900">启动中</h1>
          <p className="mt-2 text-sm text-slate-600">正在拉起后端服务并初始化前端界面。</p>

          <div className="mt-6 space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center gap-3 text-sm">
              <span className={`inline-block h-2.5 w-2.5 rounded-full ${backendConnected ? 'bg-emerald-500' : 'bg-amber-500 animate-pulse'}`} />
              <span>后端服务：{backendConnected ? '已连接' : '启动中'}</span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <span className={`inline-block h-2.5 w-2.5 rounded-full ${!backendConnected || isTSharkChecking ? 'bg-slate-400 animate-pulse' : (tsharkStatus.available ? 'bg-emerald-500' : 'bg-rose-500')}`} />
              <span>
                tshark：
                {!backendConnected || isTSharkChecking
                  ? '检测中'
                  : (tsharkStatus.available ? '可用' : (toolRuntimeCheckDegraded ? '稍后重试' : '不可用'))}
              </span>
            </div>
            <div className="text-xs text-slate-500 break-all">{backendStatus || '等待状态...'}</div>
            {backendConnected && !isTSharkChecking && (
              <div className={`text-xs break-all ${tsharkStatus.available ? 'text-emerald-600' : 'text-rose-600'}`}>
                {tsharkStatus.available
                  ? `已检测到: ${tsharkStatus.path || 'tshark'}`
                  : (tsharkStatus.message || (toolRuntimeCheckDegraded ? '检测暂时未完成，可进入主界面后刷新状态' : '未检测到 tshark'))}
              </div>
            )}
          </div>

          {backendConnected && !isTSharkChecking && !tsharkStatus.available && !toolRuntimeCheckDegraded && (
            <div className="mt-5 rounded-xl border border-rose-200 bg-rose-50 p-4">
              <div className="text-sm font-medium text-rose-700">请先配置 tshark 路径</div>
              <p className="mt-1 text-xs text-rose-600">
                可以直接填写 `tshark.exe` 的绝对路径，或者填写 Wireshark 安装目录。
              </p>
              <div className="mt-3 flex gap-2">
                <input
                  value={pathInput}
                  onChange={(event) => setPathInput(event.target.value)}
                  placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
                  className="flex-1 rounded-md border border-rose-200 bg-white px-3 py-2 text-xs text-slate-900 outline-none focus:border-blue-500"
                />
                <button
                  onClick={() => void handleSavePath()}
                  disabled={savingPath}
                  className="rounded-md border border-blue-200 bg-blue-600 px-3 py-2 text-xs font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {savingPath ? '保存中' : '保存路径'}
                </button>
              </div>
              {tsharkStatus.customPath && (
                <button
                  onClick={() => {
                    setPathInput('');
                    void handleSavePath('');
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
            <div className={`h-full rounded bg-gradient-to-r from-sky-500 to-blue-600 transition-all duration-500 ${backendConnected && (tsharkStatus.available || toolRuntimeCheckDegraded) ? 'w-full' : backendConnected ? 'w-5/6' : 'w-2/3 animate-pulse'}`} />
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
        key === 'f12' ||
        (event.ctrlKey && event.shiftKey && (key === 'i' || key === 'j' || key === 'c')) ||
        (event.ctrlKey && key === 'u');
      if (disableDevtools) {
        event.preventDefault();
      }
    };

    window.addEventListener('contextmenu', onContextMenu);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('contextmenu', onContextMenu);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  return (
    <SentinelProvider>
      <StartupGate />
    </SentinelProvider>
  );
}
