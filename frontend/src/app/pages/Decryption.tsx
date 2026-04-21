import { useState } from "react";
import { KeyRound, LockOpen, Upload, CheckCircle2, FileText, Lock } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { useSentinel } from "../state/SentinelContext";
import { bridge } from "../integrations/wailsBridge";

export default function Decryption() {
  const { decryptionConfig, updateDecryptionConfig, fileMeta, openCapture, displayFilter, setDisplayFilter, applyFilter } = useSentinel();
  const [saved, setSaved] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

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
      window.setTimeout(() => setSaved(false), 1200);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "TLS 配置应用失败");
    } finally {
      setIsApplying(false);
    }
  };

  return (
    <PageShell innerClassName="max-w-5xl px-6 py-6">
      <AnalysisHero
        icon={<LockOpen className="h-5 w-5" />}
        title="TLS 解密"
        subtitle="TLS DECRYPTION SETTINGS"
        description="统一管理 SSLKEYLOGFILE 与 RSA 私钥配置，并在应用后触发当前抓包的 TLS 重新解析。"
        tags={["TLS", "HTTPS", "SSLKEYLOGFILE", "RSA 私钥"]}
        tagsLabel="解密域"
        theme="amber"
      />
      <div className="mx-auto flex h-auto w-full max-w-3xl flex-col overflow-hidden rounded-[28px] border border-border bg-card shadow-sm">
        <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-6 py-5">
          <div className="flex items-center gap-3 text-lg font-semibold text-foreground">
            <LockOpen className="h-6 w-6 text-amber-600" /> TLS / HTTPS 流量解密配置
          </div>
        </div>

        <div className="flex flex-col gap-8 bg-card p-8">
          <div className="flex flex-col gap-3.5">
            <div className="flex items-center gap-2.5 font-medium text-foreground">
              <span className="rounded-md border border-amber-200 bg-amber-100 px-2.5 py-1 text-xs text-amber-800">方案 A</span>
              导入主密钥日志文件 (SSLKEYLOGFILE)
              <span className="ml-2 flex items-center gap-1.5 text-xs font-normal text-emerald-600">
                <CheckCircle2 className="h-4 w-4" /> 推荐 (支持 TLS 1.3 & PFS)
              </span>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex flex-1 items-center rounded-md border border-border bg-background px-3.5 py-2.5 text-sm shadow-sm transition-all hover:border-ring focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
                <FileText className="mr-2.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <input
                  type="text"
                  value={decryptionConfig.sslKeyLogPath}
                  onChange={(event) => updateDecryptionConfig({ sslKeyLogPath: event.target.value })}
                  className="flex-1 border-none bg-transparent font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
                  placeholder="选择 sslkeylog.log 文件路径"
                />
              </div>
              <button className="flex items-center gap-2 rounded-md border border-border bg-background px-5 py-2.5 text-sm font-medium text-foreground shadow-sm transition-colors hover:bg-accent">
                <Upload className="h-4 w-4 text-muted-foreground" /> 浏览
              </button>
            </div>
          </div>

          <div className="h-px w-full bg-border" />

          <div className="flex flex-col gap-3.5">
            <div className="flex items-center gap-2.5 font-medium text-muted-foreground">
              <span className="rounded-md border border-border bg-accent px-2.5 py-1 text-xs text-muted-foreground">方案 B</span>
              导入 RSA 私钥
              <span className="ml-2 flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
                <Lock className="h-4 w-4" /> 仅限 TLS 1.2 及以下，无 PFS
              </span>
            </div>
            <div className="flex items-center gap-3 transition-opacity hover:opacity-100">
              <div className="flex flex-1 items-center rounded-md border border-border bg-accent/30 px-3.5 py-2.5 text-sm transition-all hover:border-ring focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
                <KeyRound className="mr-2.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <input
                  type="text"
                  value={decryptionConfig.privateKeyPath}
                  onChange={(event) => updateDecryptionConfig({ privateKeyPath: event.target.value })}
                  className="flex-1 border-none bg-transparent font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
                  placeholder="选择 server_private.pem 文件路径"
                />
              </div>
              <button className="flex items-center gap-2 rounded-md border border-border bg-accent/30 px-5 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent">
                <Upload className="h-4 w-4 text-muted-foreground" /> 浏览
              </button>
            </div>
            <div className="rounded-md border border-border bg-accent/30 px-3.5 py-2.5 text-xs">
              <div className="mb-1 text-muted-foreground">私钥绑定目标 (IP:Port)</div>
              <input
                value={decryptionConfig.privateKeyIpPort}
                onChange={(event) => updateDecryptionConfig({ privateKeyIpPort: event.target.value })}
                className="w-full border-none bg-transparent font-mono text-foreground outline-none"
                placeholder="10.0.0.5:443"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-border bg-accent/40 px-6 py-4">
          <div className="text-xs text-muted-foreground">保存后将触发后端重新解析 TLS 流</div>
          <div className="flex items-center gap-3">
            {errorMessage && <span data-testid="tls-error" className="text-xs text-rose-600">{errorMessage}</span>}
            {saved && <span className="text-xs text-emerald-600">配置已保存</span>}
            <button className="rounded-md bg-transparent px-5 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
              取消
            </button>
            <button data-testid="tls-apply-button" onClick={() => void apply()} disabled={isApplying} className="rounded-md bg-amber-600 px-6 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-amber-700 disabled:cursor-not-allowed disabled:opacity-60">
              应用并重新加载
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
