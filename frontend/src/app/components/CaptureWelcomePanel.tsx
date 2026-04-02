import { Binary, BookOpenText, FolderOpen, History, Radar, ShieldAlert } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { formatBytes, useSentinel } from "../state/SentinelContext";

function formatRecentTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "最近打开";
  }
  return parsed.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

export function CaptureWelcomePanel() {
  const {
    backendConnected,
    backendStatus,
    tsharkStatus,
    recentCaptures,
    openCapture,
  } = useSentinel();
  const [capturePath, setCapturePath] = useState("");
  const captureActionsDisabled = !backendConnected || !tsharkStatus.available;
  const recentItems = useMemo(() => recentCaptures.slice(0, 6), [recentCaptures]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-[radial-gradient(circle_at_top_left,_rgba(37,99,235,0.12),_transparent_36%),linear-gradient(180deg,_#f8fbff_0%,_#f6f8fb_100%)] p-6 text-foreground">
      <section className="overflow-hidden rounded-[28px] border border-slate-200 bg-white/90 shadow-[0_24px_80px_-40px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-0 lg:grid-cols-[minmax(0,1.3fr)_380px]">
          <div className="border-b border-slate-200/80 p-8 lg:border-b-0 lg:border-r">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-[11px] font-semibold tracking-[0.18em] text-blue-700">
              <Radar className="h-3.5 w-3.5" />
              GSHARK QUICK START
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold tracking-tight text-slate-950">
              先帮你找到方向，再进入流量细节。
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-600">
              打开抓包后，首屏会自动总结协议特征、推荐分析入口，并把威胁命中、过滤器、流追踪和 payload 解码串成一条更顺手的路径。
            </p>

            <div className="mt-8 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto]">
              <input
                value={capturePath}
                onChange={(event) => setCapturePath(event.target.value)}
                name="welcome-capture-path"
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="直接输入 PCAP / PCAPNG 绝对路径"
                className="h-12 rounded-2xl border border-slate-200 bg-slate-50 px-4 text-sm text-slate-900 outline-none transition-all placeholder:text-slate-400 focus:border-blue-500 focus:bg-white"
              />
              <button
                onClick={() => void openCapture()}
                disabled={captureActionsDisabled}
                className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl border border-blue-200 bg-blue-600 px-5 text-sm font-medium text-white shadow-sm transition-all hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <FolderOpen className="h-4 w-4" />
                选择文件
              </button>
              <button
                onClick={() => void openCapture(capturePath.trim())}
                disabled={captureActionsDisabled || !capturePath.trim()}
                className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl border border-slate-200 bg-white px-5 text-sm font-medium text-slate-700 transition-all hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <FolderOpen className="h-4 w-4" />
                路径打开
              </button>
            </div>

            <div className="mt-6 grid gap-3 md:grid-cols-3">
              <GuideCard
                icon={<ShieldAlert className="h-4 w-4 text-rose-600" />}
                title="1. 快速找可疑流量"
                text="打开抓包后先看自动摘要和威胁命中，再决定走 Web、工控、车机、USB 还是 RTP 分析路径。"
              />
              <GuideCard
                icon={<BookOpenText className="h-4 w-4 text-emerald-600" />}
                title="2. 筛选上下文"
                text="首屏会给出推荐过滤器，点一下就能回到主工作区按协议、端口、异常会话重新聚焦。"
              />
              <GuideCard
                icon={<Binary className="h-4 w-4 text-amber-600" />}
                title="3. 快速解码 Payload"
                text="选中数据包后就能直接尝试 Base64、Behinder、AntSword、Godzilla 等解码，不必先切流页面。"
              />
            </div>
          </div>

          <div className="p-8">
            <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-5">
              <div className="text-xs font-semibold tracking-[0.18em] text-slate-500">ENGINE STATUS</div>
              <div className="mt-3 flex items-center gap-2 text-sm font-medium text-slate-900">
                <span className={`h-2.5 w-2.5 rounded-full ${backendConnected ? "bg-emerald-500" : "bg-amber-500 animate-pulse"}`} />
                {backendConnected ? "后端已连接" : "后端连接中"}
              </div>
              <div className="mt-2 flex items-center gap-2 text-sm font-medium text-slate-900">
                <span className={`h-2.5 w-2.5 rounded-full ${tsharkStatus.available ? "bg-emerald-500" : "bg-rose-500"}`} />
                {tsharkStatus.available ? `tshark 已就绪: ${tsharkStatus.path || "tshark"}` : (tsharkStatus.message || "等待配置 tshark")}
              </div>
              <div className="mt-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-xs leading-5 text-slate-600">
                {backendStatus}
              </div>
            </div>

            <div className="mt-5 rounded-[24px] border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold tracking-[0.18em] text-slate-500">RECENT FILES</div>
                  <div className="mt-1 text-sm font-medium text-slate-900">最近打开的抓包</div>
                </div>
                <History className="h-4 w-4 text-slate-400" />
              </div>

              {recentItems.length === 0 ? (
                <div className="mt-4 rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-center text-xs leading-5 text-slate-500">
                  这里会保留最近打开过的抓包路径，方便你反复对照样本与回归测试。
                </div>
              ) : (
                <div className="mt-4 space-y-3">
                  {recentItems.map((item) => (
                    <button
                      key={item.path}
                      onClick={() => void openCapture(item.path)}
                      disabled={captureActionsDisabled}
                      className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-left transition-all hover:border-blue-200 hover:bg-blue-50/60 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <div className="truncate text-sm font-medium text-slate-900">{item.name || item.path.split(/[\\/]/).pop() || item.path}</div>
                      <div className="mt-1 truncate font-mono text-[11px] text-slate-500">{item.path}</div>
                      <div className="mt-2 flex items-center justify-between text-[11px] text-slate-500">
                        <span>{formatBytes(item.sizeBytes)}</span>
                        <span>{formatRecentTime(item.lastOpenedAt)}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function GuideCard({
  icon,
  title,
  text,
}: {
  icon: ReactNode;
  title: string;
  text: string;
}) {
  return (
    <div className="rounded-[24px] border border-slate-200 bg-slate-50 px-4 py-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        {icon}
        {title}
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-600">{text}</p>
    </div>
  );
}
