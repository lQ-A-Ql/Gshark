import { CheckCircle2, Copy, Download, FileText, Play, Terminal, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { bridge } from "../../integrations/wailsBridge";
import { useSentinel } from "../../state/SentinelContext";
import type { WinRMDecryptResult } from "../../core/types";
import type { MiscModuleRendererProps } from "../types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { ErrorBlock, Field, MetaChip } from "../ui";

type WinRMPreviewMode = "full" | "extract" | "command" | "stdout" | "stderr";

interface WinRMExtractEntry {
  header: string;
  command: string;
  stdin: string;
  stdout: string;
  stderr: string;
}

const winrmPreviewModeLabels: Record<WinRMPreviewMode, string> = {
  full: "完整原文",
  extract: "仅提取结果",
  command: "仅看 Command",
  stdout: "仅看 Stdout",
  stderr: "仅看 Stderr",
};

export function WinRMDecryptModule({ module }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const [winrmPort, setWinrmPort] = useState("5985");
  const [winrmAuthMode, setWinrmAuthMode] = useState<"password" | "nt_hash">("password");
  const [winrmPassword, setWinrmPassword] = useState("");
  const [winrmHash, setWinrmHash] = useState("");
  const [winrmPreviewLines, setWinrmPreviewLines] = useState("200");
  const [winrmLoading, setWinrmLoading] = useState(false);
  const [winrmError, setWinrmError] = useState("");
  const [winrmResult, setWinrmResult] = useState<WinRMDecryptResult | null>(null);
  const [winrmPreviewOpen, setWinrmPreviewOpen] = useState(false);
  const [winrmPreviewLoading, setWinrmPreviewLoading] = useState(false);
  const [winrmPreviewDialogText, setWinrmPreviewDialogText] = useState("");
  const [winrmPreviewDialogError, setWinrmPreviewDialogError] = useState("");
  const [winrmPreviewMode, setWinrmPreviewMode] = useState<WinRMPreviewMode>("full");

  const hasCapture = Boolean(fileMeta.path);
  const normalizedWinrmPort = useMemo(() => Number(winrmPort.replace(/[^0-9]/g, "") || "0"), [winrmPort]);
  const normalizedPreviewLines = useMemo(() => Number(winrmPreviewLines.replace(/[^0-9]/g, "") || "0"), [winrmPreviewLines]);
  const winrmExtractEntries = useMemo(() => parseWinRMExtractEntries(winrmPreviewDialogText), [winrmPreviewDialogText]);
  const winrmPreviewDisplayText = useMemo(() => {
    if (winrmPreviewMode === "full") {
      return winrmPreviewDialogText;
    }
    return renderWinRMPreviewMode(winrmExtractEntries, winrmPreviewMode);
  }, [winrmExtractEntries, winrmPreviewDialogText, winrmPreviewMode]);

  async function runWinRM() {
    if (!hasCapture) {
      setWinrmError("请先在主工作区导入抓包文件");
      return;
    }
    setWinrmLoading(true);
    setWinrmError("");
    try {
      const result = await bridge.runWinRMDecrypt({
        port: normalizedWinrmPort,
        authMode: winrmAuthMode,
        password: winrmAuthMode === "password" ? winrmPassword : "",
        ntHash: winrmAuthMode === "nt_hash" ? winrmHash : "",
        previewLines: normalizedPreviewLines,
        includeErrorFrames: false,
        extractCommandOutput: true,
      });
      setWinrmResult(result);
      setWinrmPreviewOpen(false);
      setWinrmPreviewDialogText("");
      setWinrmPreviewDialogError("");
      setWinrmPreviewMode("extract");
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
    const text = await bridge.getWinRMDecryptResultText(winrmResult.resultId);
    setWinrmPreviewDialogText(text);
    return text;
  }

  async function openWinRMPreview() {
    if (!winrmResult) return;
    setWinrmPreviewMode("extract");
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
      await bridge.exportWinRMDecryptResult(winrmResult.resultId, winrmResult.exportFilename);
    } catch (error) {
      setWinrmError(error instanceof Error ? error.message : "导出失败");
    }
  }

  async function copyWinRMPreview() {
    if (!winrmResult) return;
    try {
      const text = await loadWinRMFullText();
      if (!text) return;
      await navigator.clipboard.writeText(text);
    } catch (error) {
      setWinrmError(error instanceof Error ? error.message : "复制失败");
    }
  }

  return (
    <>
      <Card className="min-w-0 overflow-hidden border-slate-200 bg-white shadow-sm">
        <CardHeader className="gap-2 border-b border-slate-100 bg-slate-50/70 pb-5">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-100 text-sky-600">
              <Terminal className="h-4 w-4" />
            </div>
            <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
          </div>
          <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6 pt-6">
          <div className="grid gap-5 md:grid-cols-2">
            <Field label="当前目标抓包" className="md:col-span-2">
              <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2.5 text-[13px] text-slate-600">
                <FileText className="h-4 w-4 text-slate-400" />
                <span className="flex-1 truncate font-medium">
                  {hasCapture ? `${fileMeta.name} (${fileMeta.path})` : "未加载抓包，请先在主工作区导入文件"}
                </span>
                {hasCapture && <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />}
              </div>
            </Field>
            <Field label="WinRM 服务端口">
              <Input value={winrmPort} onChange={(event) => setWinrmPort(event.target.value.replace(/[^0-9]/g, ""))} className="font-mono text-sm shadow-sm" placeholder="默认 5985" />
            </Field>
            <Field label="认证方式">
              <div className="relative isolate flex h-9 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
                <div
                  className={`absolute bottom-1 left-1 top-1 -z-10 w-[calc(50%-4px)] rounded-md bg-white shadow-sm ring-1 ring-slate-200/60 transition-transform duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] ${
                    winrmAuthMode === "password" ? "translate-x-0" : "translate-x-full"
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setWinrmAuthMode("password")}
                  className={`flex flex-1 items-center justify-center rounded-md text-[13px] font-semibold transition-colors duration-300 ${
                    winrmAuthMode === "password" ? "text-sky-700" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  Password (明文)
                </button>
                <button
                  type="button"
                  onClick={() => setWinrmAuthMode("nt_hash")}
                  className={`flex flex-1 items-center justify-center rounded-md text-[13px] font-semibold transition-colors duration-300 ${
                    winrmAuthMode === "nt_hash" ? "text-sky-700" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  NT Hash (哈希)
                </button>
              </div>
            </Field>
            <Field label="预览截断行数">
              <Input value={winrmPreviewLines} onChange={(event) => setWinrmPreviewLines(event.target.value.replace(/[^0-9]/g, ""))} className="font-mono text-sm shadow-sm" placeholder="200" />
            </Field>
            {winrmAuthMode === "password" ? (
              <Field label="明文密码 (Password)" className="animate-in slide-in-from-top-1 px-1 duration-300 md:col-span-2 fade-in">
                <Input type="password" value={winrmPassword} onChange={(event) => setWinrmPassword(event.target.value)} className="font-mono text-sm shadow-sm" placeholder="输入密码..." />
              </Field>
            ) : (
              <Field label="NT Hash (HEX)" className="animate-in slide-in-from-top-1 px-1 duration-300 md:col-span-2 fade-in">
                <Input value={winrmHash} onChange={(event) => setWinrmHash(event.target.value)} placeholder="例如: 31d6cfe...c089c0" className="font-mono text-sm shadow-sm" />
              </Field>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Button onClick={() => void runWinRM()} disabled={winrmLoading || !hasCapture} className="gap-2 bg-sky-600 text-white shadow-sm hover:bg-sky-700">
              <Play className="h-4 w-4" fill="currentColor" />
              {winrmLoading ? "解密分析中..." : "启动提取"}
            </Button>

            {winrmResult && (
              <>
                <div className="mx-1 h-6 w-px bg-slate-200" />
                <Button variant="outline" onClick={() => void openWinRMPreview()} className="gap-2 text-slate-700 shadow-sm">
                  <Terminal className="h-4 w-4 text-sky-600" />
                  打开预览视图
                </Button>
                <Button variant="outline" onClick={() => void exportWinRM()} className="gap-2 text-slate-700 shadow-sm">
                  <Download className="h-4 w-4 text-emerald-600" />
                  保存导出 TXT
                </Button>
                <Button variant="outline" onClick={() => void copyWinRMPreview()} className="gap-2 text-slate-700 shadow-sm">
                  <Copy className="h-4 w-4 text-blue-600" />
                  复制结果
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setWinrmResult(null);
                    setWinrmError("");
                    setWinrmPreviewOpen(false);
                    setWinrmPreviewDialogText("");
                    setWinrmPreviewDialogError("");
                    setWinrmPreviewMode("full");
                  }}
                  className="gap-2 text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                >
                  <Trash2 className="h-4 w-4" />
                  清空
                </Button>
              </>
            )}
          </div>

          {winrmError && <div className="animate-in slide-in-from-bottom-2 duration-300 fade-in"><ErrorBlock message={winrmError} /></div>}
          {winrmResult && (
            <div className="mt-4 animate-in slide-in-from-bottom-2 duration-300 fade-in">
              <div className="flex flex-wrap gap-2 rounded-xl border border-sky-100 bg-sky-50/50 p-4 text-[11px] shadow-sm">
                <MetaChip label="抓包" value={winrmResult.captureName} />
                <MetaChip label="Port" value={winrmResult.port} />
                <MetaChip label="Mode" value={winrmResult.authMode} />
                <MetaChip label="总帧" value={winrmResult.frameCount} />
                <MetaChip label="解密失败" value={winrmResult.errorFrameCount} color="rose" />
                <MetaChip label="含Payload帧" value={winrmResult.extractedFrameCount} color="sky" />
                <MetaChip label="输出行数" value={winrmResult.lineCount} color="emerald" />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={winrmPreviewOpen} onOpenChange={setWinrmPreviewOpen}>
        <DialogContent className="max-h-[90vh] max-w-6xl overflow-hidden p-0">
          <DialogHeader className="border-b border-slate-100 px-6 py-5">
            <DialogTitle>{module.title}结果预览</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 bg-slate-50/50 px-6 py-5">
            {winrmPreviewDialogError && <ErrorBlock message={winrmPreviewDialogError} />}
            {!winrmPreviewLoading && !winrmPreviewDialogError && (
              <div className="flex flex-wrap items-center gap-2">
                {(["full", "extract", "command", "stdout", "stderr"] as WinRMPreviewMode[]).map((mode) => (
                  <Button
                    key={mode}
                    variant={winrmPreviewMode === mode ? "default" : "outline"}
                    size="sm"
                    onClick={() => setWinrmPreviewMode(mode)}
                    className={winrmPreviewMode === mode ? "shadow-sm" : "bg-white"}
                  >
                    {winrmPreviewModeLabels[mode]}
                  </Button>
                ))}
                {winrmExtractEntries.length > 0 && (
                  <span className="ml-2 inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600 shadow-sm">
                    已解析 {winrmExtractEntries.length} 个提取块
                  </span>
                )}
              </div>
            )}
            {winrmPreviewLoading ? (
              <div className="rounded-lg border border-slate-200 bg-white px-4 py-8 text-center text-sm font-medium text-slate-500 shadow-sm">正在加载完整结果...</div>
            ) : (
              <pre className="max-h-[68vh] min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-slate-200 bg-white p-5 font-mono text-[13px] leading-relaxed text-slate-800 shadow-sm selection:bg-sky-100">
                {winrmPreviewDisplayText || "(empty result)"}
              </pre>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function parseWinRMExtractEntries(raw: string): WinRMExtractEntry[] {
  const lines = raw.replaceAll("\r\n", "\n").split("\n");
  const entries: WinRMExtractEntry[] = [];
  let currentHeader = "";
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    if (line.startsWith("No: ")) {
      currentHeader = line.trim();
      index++;
      continue;
    }
    if (line.trim() !== "[extract]") {
      index++;
      continue;
    }

    const entry: WinRMExtractEntry = {
      header: currentHeader || "No: unknown frame",
      command: "",
      stdin: "",
      stdout: "",
      stderr: "",
    };
    index++;
    let currentField: keyof Omit<WinRMExtractEntry, "header"> | null = null;
    let buffer: string[] = [];

    const flush = () => {
      if (!currentField) return;
      entry[currentField] = buffer.join("\n").replace(/\s+$/g, "");
      currentField = null;
      buffer = [];
    };

    while (index < lines.length) {
      const currentLine = lines[index];
      if (currentLine.startsWith("No: ") || currentLine.trim() === "[extract]") {
        break;
      }

      const fieldName = currentLine.trim().replace(/:$/, "");
      if (fieldName === "command" || fieldName === "stdin" || fieldName === "stdout" || fieldName === "stderr") {
        flush();
        currentField = fieldName;
        index++;
        continue;
      }

      if (!currentField) {
        if (currentLine.trim() === "") {
          index++;
          continue;
        }
        break;
      }

      if (currentLine.startsWith("  ")) {
        buffer.push(currentLine.slice(2));
        index++;
        continue;
      }
      if (currentLine === "") {
        buffer.push("");
        index++;
        continue;
      }
      break;
    }

    flush();
    if (entry.command || entry.stdin || entry.stdout || entry.stderr) {
      entries.push(entry);
    }
  }

  return entries;
}

function renderWinRMPreviewMode(entries: WinRMExtractEntry[], mode: Exclude<WinRMPreviewMode, "full">): string {
  if (entries.length === 0) {
    return "当前结果中没有可展示的提取块。请确认该抓包里存在可提取的 WinRM command 或回显内容。";
  }

  const blocks = entries
    .map((entry) => formatWinRMExtractEntry(entry, mode))
    .filter((block) => block.length > 0);

  if (blocks.length === 0) {
    return `当前结果里没有可展示的 ${winrmPreviewModeLabels[mode]} 内容。`;
  }
  return blocks.join("\n\n");
}

function formatWinRMExtractEntry(entry: WinRMExtractEntry, mode: Exclude<WinRMPreviewMode, "full">): string {
  const sections: string[] = [];
  if (mode === "extract") {
    if (entry.command) sections.push("command:\n" + indentPreviewText(entry.command));
    if (entry.stdin) sections.push("stdin:\n" + indentPreviewText(entry.stdin));
    if (entry.stdout) sections.push("stdout:\n" + indentPreviewText(entry.stdout));
    if (entry.stderr) sections.push("stderr:\n" + indentPreviewText(entry.stderr));
  }
  if (mode === "command" && entry.command) sections.push("command:\n" + indentPreviewText(entry.command));
  if (mode === "stdout" && entry.stdout) sections.push("stdout:\n" + indentPreviewText(entry.stdout));
  if (mode === "stderr" && entry.stderr) sections.push("stderr:\n" + indentPreviewText(entry.stderr));
  if (sections.length === 0) {
    return "";
  }
  return entry.header + "\n" + sections.join("\n");
}

function indentPreviewText(raw: string): string {
  return raw.split("\n").map((line) => `  ${line}`).join("\n");
}
