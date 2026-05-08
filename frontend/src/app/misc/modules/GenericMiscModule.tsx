import { Loader2, Play, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import type { MiscModuleTableResult } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import type { MiscModuleRendererProps } from "../types";
import { ErrorBlock } from "../ui";
import { buildInitialValues, GenericMiscFormFields } from "./GenericMiscFormFields";
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

  const tags = useMemo(() => {
    const runtime = module.interfaceSchema?.runtime ? [`Runtime:${module.interfaceSchema.runtime}`] : [];
    return [...module.tags, ...runtime];
  }, [module.interfaceSchema?.runtime, module.tags]);

  async function handleRun() {
    if (!hasSchemaForm) return;
    setRunning(true);
    setError("");
    setResultText("");
    setResultJSON("");
    setResultTable(undefined);
    try {
      const payload = await bridge.runMiscModule(module.id, values);
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
      await bridge.deleteMiscModule(module.id);
      await onModuleDeleted?.(module.id);
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "删除模块失败");
    } finally {
      setDeleting(false);
    }
  }

  const body = (
    <div
      className={
        embedded ? "space-y-5" : "space-y-5 rounded-b-xl bg-gradient-to-b from-white via-white to-slate-50/80 pt-6"
      }
    >
      {embedded ? (
        <div className="flex flex-wrap items-start justify-between gap-3 rounded-2xl border border-cyan-100 bg-gradient-to-r from-cyan-50 via-sky-50 to-white px-4 py-3">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="border-cyan-200 bg-white text-cyan-800 shadow-sm">
                {module.kind === "custom" ? "Custom" : "Builtin"}
              </Badge>
              {module.interfaceSchema?.runtime ? (
                <Badge variant="outline" className="border-cyan-200 bg-white text-cyan-800 shadow-sm">
                  {module.interfaceSchema.runtime}
                </Badge>
              ) : null}
            </div>
            {module.formSchema?.description ? (
              <div className="text-[13px] leading-relaxed text-slate-600">{module.formSchema.description}</div>
            ) : null}
          </div>
          {canDelete ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-rose-200 bg-white text-rose-700 shadow-sm hover:bg-rose-50"
              onClick={() => void handleDelete()}
              disabled={deleting || running}
            >
              {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              {deleting ? "删除中..." : "删除模块"}
            </Button>
          ) : null}
        </div>
      ) : null}

      <div className="flex flex-wrap gap-2">
        {tags.map((tag) => (
          <Badge
            key={`${module.id}-${tag}`}
            variant="outline"
            className="rounded-full border-cyan-100 bg-cyan-50/70 px-2.5 py-1 text-[11px] font-semibold text-cyan-800 shadow-sm"
          >
            {tag}
          </Badge>
        ))}
      </div>

      <div className="flex flex-wrap gap-2 text-[11px]">
        <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
          {module.requiresCapture ? "需要抓包" : "无需抓包"}
        </Badge>
        {module.protocolDomain ? (
          <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
            域: {module.protocolDomain}
          </Badge>
        ) : null}
        {module.supportsExport ? (
          <Badge variant="outline" className="rounded-full border-emerald-200 bg-emerald-50 text-emerald-700">
            支持导出
          </Badge>
        ) : null}
        <Badge
          variant="outline"
          title={
            module.cancellable
              ? "该模块的分析请求支持中途取消或切换时自动中断"
              : "该模块当前按同步请求执行，没有单独的中断能力位"
          }
          className={`rounded-full ${module.cancellable ? "border-amber-200 bg-amber-50 text-amber-700" : "border-slate-200 bg-slate-50 text-slate-700"}`}
        >
          {module.cancellable ? "支持中断" : "同步执行"}
        </Badge>
        {(module.dependsOn?.length ?? 0) > 0 ? (
          <Badge variant="outline" className="rounded-full border-slate-200 bg-slate-50 text-slate-700">
            依赖: {module.dependsOn!.join(", ")}
          </Badge>
        ) : null}
      </div>

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
    </div>
  );

  if (embedded) {
    return body;
  }

  return (
    <Card className="group relative min-w-0 overflow-visible border-cyan-100/80 bg-white shadow-[0_18px_55px_rgba(15,23,42,0.08)] ring-1 ring-cyan-50/80 transition-all duration-300 hover:-translate-y-0.5 hover:border-cyan-200 hover:shadow-[0_26px_70px_rgba(8,145,178,0.14)]">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-1 rounded-t-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-indigo-500" />
      <CardHeader className="relative gap-3 rounded-t-xl border-b border-cyan-100/70 bg-[radial-gradient(circle_at_12%_20%,rgba(34,211,238,0.22),transparent_34%),linear-gradient(135deg,#f8fafc_0%,#ecfeff_52%,#eff6ff_100%)] pb-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="border-cyan-200 bg-white/80 text-cyan-700 shadow-sm backdrop-blur">
                {module.kind === "custom" ? "Custom" : "Builtin"}
              </Badge>
              {module.interfaceSchema?.runtime ? (
                <Badge variant="outline" className="border-blue-200 bg-blue-50 text-blue-700 shadow-sm backdrop-blur">
                  {module.interfaceSchema.runtime}
                </Badge>
              ) : null}
            </div>
            <CardTitle className="break-words text-lg font-semibold tracking-tight text-slate-900">
              {module.title}
            </CardTitle>
          </div>
          {canDelete ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-rose-200 bg-white/80 text-rose-600 shadow-sm backdrop-blur hover:border-rose-300 hover:bg-rose-50 hover:text-rose-700"
              onClick={() => void handleDelete()}
              disabled={deleting || running}
            >
              {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              {deleting ? "删除中..." : "删除模块"}
            </Button>
          ) : null}
        </div>
        <CardDescription className="max-w-3xl text-[13px] leading-relaxed text-slate-600">
          {module.summary}
        </CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  );
}
