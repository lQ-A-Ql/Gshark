import { CheckCircle2, FileText } from "lucide-react";
import { Input } from "../../components/ui/input";
import { Field } from "../ui";
import { sanitizeWinRMNumericInput, type WinRMAuthMode } from "./WinRMDecryptUtils";
export type { WinRMAuthMode } from "./WinRMDecryptUtils";

interface WinRMDecryptFormProps {
  authMode: WinRMAuthMode;
  captureName: string;
  capturePath: string;
  hasCapture: boolean;
  hash: string;
  onAuthModeChange: (value: WinRMAuthMode) => void;
  onHashChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onPortChange: (value: string) => void;
  onPreviewLinesChange: (value: string) => void;
  password: string;
  port: string;
  previewLines: string;
}

export function WinRMDecryptForm({
  authMode,
  captureName,
  capturePath,
  hasCapture,
  hash,
  onAuthModeChange,
  onHashChange,
  onPasswordChange,
  onPortChange,
  onPreviewLinesChange,
  password,
  port,
  previewLines,
}: WinRMDecryptFormProps) {
  return (
    <div className="grid gap-5 md:grid-cols-2">
      <Field label="当前目标抓包" className="md:col-span-2">
        <div className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2.5 text-[13px] text-slate-600">
          <FileText className="h-4 w-4 text-slate-400" />
          <span className="flex-1 truncate font-medium">
            {hasCapture ? `${captureName} (${capturePath})` : "未加载抓包，请先在主工作区导入文件"}
          </span>
          {hasCapture && <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />}
        </div>
      </Field>
      <Field label="WinRM 服务端口">
        <Input
          value={port}
          onChange={(event) => onPortChange(sanitizeWinRMNumericInput(event.target.value))}
          className="font-mono text-sm shadow-sm"
          placeholder="默认 5985"
        />
      </Field>
      <Field label="认证方式">
        <div className="relative isolate flex h-9 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
          <div
            className={`absolute bottom-1 left-1 top-1 -z-10 w-[calc(50%-4px)] rounded-md bg-white shadow-sm ring-1 ring-slate-200/60 transition-transform duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] ${
              authMode === "password" ? "translate-x-0" : "translate-x-full"
            }`}
          />
          <button
            type="button"
            onClick={() => onAuthModeChange("password")}
            className={`flex flex-1 items-center justify-center rounded-md text-[13px] font-semibold transition-colors duration-300 ${
              authMode === "password" ? "text-sky-700" : "text-slate-500 hover:text-slate-700"
            }`}
          >
            Password (明文)
          </button>
          <button
            type="button"
            onClick={() => onAuthModeChange("nt_hash")}
            className={`flex flex-1 items-center justify-center rounded-md text-[13px] font-semibold transition-colors duration-300 ${
              authMode === "nt_hash" ? "text-sky-700" : "text-slate-500 hover:text-slate-700"
            }`}
          >
            NT Hash (哈希)
          </button>
        </div>
      </Field>
      <Field label="预览截断行数">
        <Input
          value={previewLines}
          onChange={(event) => onPreviewLinesChange(sanitizeWinRMNumericInput(event.target.value))}
          className="font-mono text-sm shadow-sm"
          placeholder="200"
        />
      </Field>
      {authMode === "password" ? (
        <Field
          label="明文密码 (Password)"
          className="animate-in slide-in-from-top-1 px-1 duration-300 md:col-span-2 fade-in"
        >
          <Input
            type="password"
            value={password}
            onChange={(event) => onPasswordChange(event.target.value)}
            className="font-mono text-sm shadow-sm"
            placeholder="输入密码..."
          />
        </Field>
      ) : (
        <Field label="NT Hash (HEX)" className="animate-in slide-in-from-top-1 px-1 duration-300 md:col-span-2 fade-in">
          <Input
            value={hash}
            onChange={(event) => onHashChange(event.target.value)}
            placeholder="例如: 31d6cfe...c089c0"
            className="font-mono text-sm shadow-sm"
          />
        </Field>
      )}
    </div>
  );
}
