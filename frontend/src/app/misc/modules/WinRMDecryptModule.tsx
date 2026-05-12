import { Terminal } from "lucide-react";
import { useState } from "react";
import { backendClients } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { WinRMDecryptResult } from "../../core/types";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { ErrorBlock } from "../ui";
import { copyTextToClipboard } from "../../utils/browserFile";
import { WinRMDecryptActions } from "./WinRMDecryptActions";
import { WinRMDecryptForm, type WinRMAuthMode } from "./WinRMDecryptForm";
import { WinRMPreviewDialog } from "./WinRMPreviewDialog";
import { WinRMResultSummary } from "./WinRMResultSummary";
import {
  buildWinRMDecryptRequest,
  DEFAULT_WINRM_PORT,
  DEFAULT_WINRM_PREVIEW_LINES,
  getWinRMResultResetState,
} from "./WinRMDecryptUtils";

export function WinRMDecryptModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const [winrmPort, setWinrmPort] = useState(DEFAULT_WINRM_PORT);
  const [winrmAuthMode, setWinrmAuthMode] = useState<WinRMAuthMode>("password");
  const [winrmPassword, setWinrmPassword] = useState("");
  const [winrmHash, setWinrmHash] = useState("");
  const [winrmPreviewLines, setWinrmPreviewLines] = useState(DEFAULT_WINRM_PREVIEW_LINES);
  const [winrmLoading, setWinrmLoading] = useState(false);
  const [winrmError, setWinrmError] = useState("");
  const [winrmResult, setWinrmResult] = useState<WinRMDecryptResult | null>(null);
  const [winrmPreviewOpen, setWinrmPreviewOpen] = useState(false);
  const [winrmPreviewLoading, setWinrmPreviewLoading] = useState(false);
  const [winrmPreviewDialogText, setWinrmPreviewDialogText] = useState("");
  const [winrmPreviewDialogError, setWinrmPreviewDialogError] = useState("");

  const hasCapture = Boolean(fileMeta.path);
  const embedded = surfaceVariant === "embedded";

  async function runWinRM() {
    if (!hasCapture) {
      setWinrmError("请先在主工作区导入抓包文件");
      return;
    }
    setWinrmLoading(true);
    setWinrmError("");
    try {
      const result = await backendClients.securityMaterial.runWinRMDecrypt(
        buildWinRMDecryptRequest({
          authMode: winrmAuthMode,
          hash: winrmHash,
          password: winrmPassword,
          port: winrmPort,
          previewLines: winrmPreviewLines,
        }),
      );
      setWinrmResult(result);
      setWinrmPreviewOpen(false);
      setWinrmPreviewDialogText("");
      setWinrmPreviewDialogError("");
    } catch (error) {
      setWinrmError(error instanceof Error ? error.message : "WinRM 解密失败");
      setWinrmResult(null);
    } finally {
      setWinrmLoading(false);
    }
  }

  async function loadWinRMFullText(force = false) {
    if (!winrmResult) return "";
    if (!force && winrmPreviewDialogText) {
      return winrmPreviewDialogText;
    }
    const text = await backendClients.securityMaterial.getWinRMDecryptResultText(winrmResult.resultId);
    setWinrmPreviewDialogText(text);
    return text;
  }

  async function openWinRMPreview() {
    if (!winrmResult) return;
    setWinrmPreviewOpen(true);
    setWinrmPreviewLoading(true);
    setWinrmPreviewDialogError("");
    try {
      await loadWinRMFullText();
    } catch (error) {
      setWinrmPreviewDialogError(error instanceof Error ? error.message : "加载预览失败");
    } finally {
      setWinrmPreviewLoading(false);
    }
  }

  async function exportWinRM() {
    if (!winrmResult) return;
    try {
      await backendClients.securityMaterial.exportWinRMDecryptResult(winrmResult.resultId, winrmResult.exportFilename);
    } catch (error) {
      setWinrmError(error instanceof Error ? error.message : "导出失败");
    }
  }

  async function copyWinRMPreview() {
    if (!winrmResult) return;
    try {
      const text = await loadWinRMFullText();
      if (!text) return;
      if (!(await copyTextToClipboard(text))) {
        throw new Error("复制失败");
      }
    } catch (error) {
      setWinrmError(error instanceof Error ? error.message : "复制失败");
    }
  }

  function clearWinRMResult() {
    const resetState = getWinRMResultResetState();
    setWinrmResult(resetState.result);
    setWinrmError(resetState.error);
    setWinrmPreviewOpen(resetState.previewOpen);
    setWinrmPreviewDialogText(resetState.previewDialogText);
    setWinrmPreviewDialogError(resetState.previewDialogError);
  }

  return (
    <>
      <Card
        className={
          embedded
            ? "min-w-0 border-0 bg-transparent shadow-none"
            : "min-w-0 overflow-hidden border-slate-200 bg-white shadow-sm"
        }
      >
        <CardHeader className={embedded ? "hidden" : "gap-2 border-b border-slate-100 bg-slate-50/70 pb-5"}>
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-100 text-sky-600">
              <Terminal className="h-4 w-4" />
            </div>
            <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
          </div>
          <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
        </CardHeader>
        <CardContent className={embedded ? "space-y-6 px-0 pt-0" : "space-y-6 pt-6"}>
          <WinRMDecryptForm
            authMode={winrmAuthMode}
            captureName={fileMeta.name}
            capturePath={fileMeta.path}
            hasCapture={hasCapture}
            hash={winrmHash}
            onAuthModeChange={setWinrmAuthMode}
            onHashChange={setWinrmHash}
            onPasswordChange={setWinrmPassword}
            onPortChange={setWinrmPort}
            onPreviewLinesChange={setWinrmPreviewLines}
            password={winrmPassword}
            port={winrmPort}
            previewLines={winrmPreviewLines}
          />

          <WinRMDecryptActions
            hasCapture={hasCapture}
            hasResult={Boolean(winrmResult)}
            loading={winrmLoading}
            onClear={clearWinRMResult}
            onCopy={() => void copyWinRMPreview()}
            onExport={() => void exportWinRM()}
            onOpenPreview={() => void openWinRMPreview()}
            onRun={() => void runWinRM()}
          />

          {winrmError && (
            <div className="animate-in slide-in-from-bottom-2 duration-300 fade-in">
              <ErrorBlock message={winrmError} />
            </div>
          )}
          {winrmResult && <WinRMResultSummary result={winrmResult} />}
        </CardContent>
      </Card>

      <WinRMPreviewDialog
        error={winrmPreviewDialogError}
        loading={winrmPreviewLoading}
        onOpenChange={setWinrmPreviewOpen}
        open={winrmPreviewOpen}
        text={winrmPreviewDialogText}
        title={module.title}
      />
    </>
  );
}
