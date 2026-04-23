import { useEffect, useRef, useState } from "react";
import { CheckCircle2, FileText, KeyRound, Loader2, Lock, LockOpen, Upload } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { useSentinel } from "../state/SentinelContext";
import { bridge } from "../integrations/wailsBridge";

interface TLSDecryptionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function TLSDecryptionDialog({ open, onOpenChange }: TLSDecryptionDialogProps) {
  const { decryptionConfig, updateDecryptionConfig, fileMeta, openCapture, displayFilter, setDisplayFilter, applyFilter } = useSentinel();
  const [saved, setSaved] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const savedTimerRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    return () => {
      if (savedTimerRef.current !== undefined) {
        window.clearTimeout(savedTimerRef.current);
      }
    };
  }, []);

  const apply = async () => {
    setIsApplying(true);
    setErrorMessage("");
    try {
      await bridge.updateTLSConfig(decryptionConfig);
      if (fileMeta.path) {
        const currentFilter = displayFilter;
        await openCapture(fileMeta.path);
        if (currentFilter) {
          setDisplayFilter(currentFilter);
          applyFilter(currentFilter);
        }
      }
      setSaved(true);
      if (savedTimerRef.current !== undefined) {
        window.clearTimeout(savedTimerRef.current);
      }
      savedTimerRef.current = window.setTimeout(() => setSaved(false), 1400);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "TLS 配置应用失败");
    } finally {
      setIsApplying(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl overflow-hidden border-amber-100 bg-white p-0 shadow-[0_30px_80px_rgba(15,23,42,0.22)]">
        <DialogHeader className="border-b border-amber-100 bg-gradient-to-br from-amber-50 via-white to-slate-50 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-amber-200 bg-amber-100 text-amber-700 shadow-inner">
              <LockOpen className="h-5 w-5" />
            </div>
            <div>
              <DialogTitle className="text-xl text-slate-900">TLS / HTTPS 解密配置</DialogTitle>
              <DialogDescription className="mt-1 text-[13px] text-slate-500">
                配置 SSLKEYLOGFILE 或 RSA 私钥；应用后会重新解析当前抓包中的 TLS 流量。
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-6 bg-[linear-gradient(180deg,#ffffff_0%,#f8fafc_100%)] px-6 py-6">
          <section className="rounded-2xl border border-amber-100 bg-white p-4 shadow-sm">
            <div className="mb-3 flex flex-wrap items-center gap-2.5">
              <span className="rounded-lg border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-800">方案 A</span>
              <span className="font-medium text-slate-900">导入主密钥日志文件</span>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-1 text-xs text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5" /> 推荐，支持 TLS 1.3 / PFS
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex min-w-0 flex-1 items-center rounded-xl border border-slate-200 bg-slate-50/80 px-3.5 py-2.5 text-sm shadow-inner transition-all hover:border-amber-200 focus-within:border-amber-400 focus-within:bg-white focus-within:ring-4 focus-within:ring-amber-100/70">
                <FileText className="mr-2.5 h-4 w-4 shrink-0 text-slate-400" />
                <input
                  type="text"
                  value={decryptionConfig.sslKeyLogPath}
                  onChange={(event) => updateDecryptionConfig({ sslKeyLogPath: event.target.value })}
                  className="min-w-0 flex-1 border-none bg-transparent font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none"
                  placeholder="C:\\Users\\you\\sslkeylog.log"
                />
              </div>
              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 shadow-sm transition hover:border-amber-200 hover:bg-amber-50 hover:text-amber-800"
              >
                <Upload className="h-4 w-4 text-slate-400" /> 浏览
              </button>
            </div>
          </section>

          <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="mb-3 flex flex-wrap items-center gap-2.5">
              <span className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-600">方案 B</span>
              <span className="font-medium text-slate-700">导入 RSA 私钥</span>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-500">
                <Lock className="h-3.5 w-3.5" /> 仅限 TLS 1.2 及以下，无 PFS
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex min-w-0 flex-1 items-center rounded-xl border border-slate-200 bg-slate-50/80 px-3.5 py-2.5 text-sm shadow-inner transition-all hover:border-slate-300 focus-within:border-blue-400 focus-within:bg-white focus-within:ring-4 focus-within:ring-blue-100/70">
                <KeyRound className="mr-2.5 h-4 w-4 shrink-0 text-slate-400" />
                <input
                  type="text"
                  value={decryptionConfig.privateKeyPath}
                  onChange={(event) => updateDecryptionConfig({ privateKeyPath: event.target.value })}
                  className="min-w-0 flex-1 border-none bg-transparent font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none"
                  placeholder="C:\\certs\\server_private.pem"
                />
              </div>
              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50"
              >
                <Upload className="h-4 w-4 text-slate-400" /> 浏览
              </button>
            </div>
            <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50/70 px-3.5 py-2.5 text-xs">
              <div className="mb-1 font-medium text-slate-500">私钥绑定目标 IP:Port</div>
              <input
                value={decryptionConfig.privateKeyIpPort}
                onChange={(event) => updateDecryptionConfig({ privateKeyIpPort: event.target.value })}
                className="w-full border-none bg-transparent font-mono text-slate-900 outline-none placeholder:text-slate-400"
                placeholder="10.0.0.5:443"
              />
            </div>
          </section>
        </div>

        <DialogFooter className="items-center justify-between border-t border-slate-200 bg-slate-50 px-6 py-4 sm:justify-between">
          <div className="min-h-5 text-xs">
            {errorMessage ? <span data-testid="tls-error" className="text-rose-600">{errorMessage}</span> : null}
            {saved ? <span className="text-emerald-600">配置已保存</span> : null}
            {!errorMessage && !saved ? <span className="text-slate-500">保存后将触发后端重新解析 TLS 流</span> : null}
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              className="rounded-xl border border-slate-200 bg-white px-5 py-2 text-sm font-medium text-slate-600 shadow-sm transition hover:bg-slate-100 hover:text-slate-900"
            >
              取消
            </button>
            <button
              data-testid="tls-apply-button"
              type="button"
              onClick={() => void apply()}
              disabled={isApplying}
              className="inline-flex items-center gap-2 rounded-xl bg-amber-600 px-5 py-2 text-sm font-semibold text-white shadow-[0_12px_28px_rgba(217,119,6,0.25)] transition hover:bg-amber-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isApplying ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {isApplying ? "应用中..." : "应用并重新加载"}
            </button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
