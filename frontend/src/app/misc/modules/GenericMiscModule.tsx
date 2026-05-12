import { Loader2, Play } from "lucide-react";
import { useState } from "react";
import { Button } from "../../components/ui/button";
import type { MiscModuleTableResult } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import type { MiscModuleRendererProps } from "../types";
import { ErrorBlock } from "../ui";
import { buildInitialValues, GenericMiscFormFields } from "./GenericMiscFormFields";
import { GenericMiscModuleChrome } from "./GenericMiscModuleChrome";
import { GenericMiscResultPanel } from "./GenericMiscResultPanel";

export function GenericMiscModule({ module, onModuleDeleted, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const [values, setValues] = useState<Record<string, string>>(() => buildInitialValues(module.formSchema?.fields));
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const [resultText, setResultText] = useState("");
  const [resultJSON, setResultJSON] = useState<string>("");
  const [resultTable, setResultTable] = useState<MiscModuleTableResult | undefined>(undefined);

  const hasSchemaForm = Boolean(module.formSchema?.fields?.length && module.interfaceSchema?.invokePath);
  const resultTitle = module.formSchema?.resultTitle ?? "模块结果";
  const canDelete = module.kind === "custom";
  const embedded = surfaceVariant === "embedded";

  async function handleRun() {
    if (!hasSchemaForm) return;
    setRunning(true);
    setError("");
    setResultText("");
    setResultJSON("");
    setResultTable(undefined);
    try {
      const payload = await backendClients.miscModule.runMiscModule(module.id, values);
      setResultText(payload.text ?? "");
      setResultJSON(payload.output === undefined ? "" : JSON.stringify(payload.output, null, 2));
      setResultTable(payload.table);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "模块执行失败");
    } finally {
      setRunning(false);
    }
  }

  async function handleDelete() {
    if (!canDelete || deleting) return;
    const confirmed = window.confirm(`确认删除已安装模块“${module.title}”吗？`);
    if (!confirmed) return;
    setDeleting(true);
    setError("");
    try {
      await backendClients.miscModule.deleteMiscModule(module.id);
      await onModuleDeleted?.(module.id);
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "删除模块失败");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <GenericMiscModuleChrome
      module={module}
      surfaceVariant={surfaceVariant}
      canDelete={canDelete}
      deleting={deleting}
      running={running}
      onDelete={() => void handleDelete()}
    >
      {hasSchemaForm ? (
        <>
          {!embedded && module.formSchema?.description ? (
            <div className="rounded-2xl border border-cyan-100 bg-gradient-to-br from-cyan-50 via-sky-50 to-white px-4 py-3 text-[13px] leading-relaxed text-cyan-900 shadow-inner shadow-white/50">
              {module.formSchema.description}
            </div>
          ) : null}

          <GenericMiscFormFields
            moduleId={module.id}
            fields={module.formSchema?.fields ?? []}
            values={values}
            running={running}
            onValueChange={(fieldName, next) => {
              setValues((current) => ({ ...current, [fieldName]: next }));
            }}
          />

          <div className="flex flex-col gap-3 rounded-2xl border border-cyan-100 bg-gradient-to-br from-slate-50 via-cyan-50/50 to-white p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0 space-y-1 text-xs text-slate-500">
              <div className="font-semibold uppercase tracking-[0.2em] text-cyan-700/80">Invoke endpoint</div>
              <div className="break-all rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 font-mono text-[11px] text-slate-700 shadow-inner">
                {module.interfaceSchema?.invokePath}
              </div>
            </div>
            <Button
              type="button"
              onClick={() => void handleRun()}
              disabled={running}
              className="h-11 min-w-32 rounded-xl bg-gradient-to-r from-cyan-500 via-sky-500 to-indigo-500 px-5 font-semibold text-white shadow-[0_12px_28px_rgba(14,165,233,0.32)] hover:from-cyan-400 hover:via-sky-500 hover:to-indigo-500"
            >
              {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {running ? "运行中..." : (module.formSchema?.submitLabel ?? "运行模块")}
            </Button>
          </div>

          {error ? <ErrorBlock message={error} /> : null}

          <GenericMiscResultPanel
            moduleId={module.id}
            resultJSON={resultJSON}
            resultTable={resultTable}
            resultText={resultText}
            resultTitle={resultTitle}
          />
        </>
      ) : (
        <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-4 text-[13px] text-slate-600 shadow-inner">
          <div className="font-semibold text-slate-800">已注册模块</div>
          <div className="mt-2 break-all">
            API 前缀:{" "}
            <span className="rounded bg-white px-1.5 py-0.5 font-mono text-slate-700 shadow-sm">
              {module.apiPrefix}
            </span>
          </div>
          {module.docsPath ? (
            <div className="mt-1 break-all">
              文档:{" "}
              <span className="rounded bg-white px-1.5 py-0.5 font-mono text-slate-700 shadow-sm">
                {module.docsPath}
              </span>
            </div>
          ) : null}
          <div className="mt-3 leading-relaxed">
            当前模块已经接入后端注册表。若需要完整交互界面，请为该模块补充 `form.json` 与
            `api.json`，即可自动使用统一卡片模板。
          </div>
        </div>
      )}
    </GenericMiscModuleChrome>
  );
}
