import { Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import type { MiscModuleTableResult } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import type { MiscModuleFormField } from "../../core/types";
import type { MiscModuleRendererProps } from "../types";
import { ErrorBlock, Field } from "../ui";

function buildInitialValues(module: MiscModuleRendererProps["module"]): Record<string, string> {
  const entries = module.formSchema?.fields ?? [];
  return entries.reduce<Record<string, string>>((acc, field) => {
    acc[field.name] = field.defaultValue ?? "";
    return acc;
  }, {});
}

function renderField(
  field: MiscModuleFormField,
  value: string,
  onChange: (next: string) => void,
  disabled: boolean,
) {
  const commonClass = "border-slate-200 bg-white text-slate-900";
  if (field.type === "textarea") {
    return (
      <textarea
        value={value}
        disabled={disabled}
        rows={field.rows ?? 6}
        placeholder={field.placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={`min-h-[120px] w-full rounded-md border px-3 py-2 text-sm shadow-sm outline-none transition focus:border-sky-300 focus:ring-2 focus:ring-sky-100 disabled:cursor-not-allowed disabled:opacity-60 ${commonClass}`}
      />
    );
  }
  if (field.type === "select") {
    return (
      <select
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        className={`h-10 w-full rounded-md border px-3 text-sm shadow-sm outline-none transition focus:border-sky-300 focus:ring-2 focus:ring-sky-100 disabled:cursor-not-allowed disabled:opacity-60 ${commonClass}`}
      >
        <option value="">{field.placeholder ?? "请选择"}</option>
        {(field.options ?? []).map((option) => (
          <option key={`${field.name}-${option.value}`} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    );
  }
  return (
    <Input
      value={value}
      disabled={disabled}
      type={field.secret ? "password" : field.type === "number" ? "number" : "text"}
      placeholder={field.placeholder}
      onChange={(event) => onChange(event.target.value)}
      className={commonClass}
    />
  );
}

export function GenericMiscModule({ module, onModuleDeleted }: MiscModuleRendererProps) {
  const [values, setValues] = useState<Record<string, string>>(() => buildInitialValues(module));
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");
  const [resultText, setResultText] = useState("");
  const [resultJSON, setResultJSON] = useState<string>("");
  const [resultTable, setResultTable] = useState<MiscModuleTableResult | undefined>(undefined);

  const hasSchemaForm = Boolean(module.formSchema?.fields?.length && module.interfaceSchema?.invokePath);
  const resultTitle = module.formSchema?.resultTitle ?? "模块结果";
  const canDelete = module.kind === "custom";

  const tags = useMemo(() => {
    const runtime = module.interfaceSchema?.runtime ? [`Runtime:${module.interfaceSchema.runtime}`] : [];
    return [...module.tags, ...runtime];
  }, [module.interfaceSchema?.runtime, module.tags]);

  async function handleRun() {
    if (!hasSchemaForm) {
      return;
    }
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
    if (!canDelete || deleting) {
      return;
    }
    const confirmed = window.confirm(`确认删除已安装模块“${module.title}”吗？`);
    if (!confirmed) {
      return;
    }
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

  return (
    <Card className="min-w-0 overflow-hidden border-slate-200 bg-white shadow-sm">
      <CardHeader className="gap-2 border-b border-slate-100 bg-slate-50/70 pb-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-amber-200 bg-amber-50 text-amber-700">
              {module.kind === "custom" ? "Custom" : "Builtin"}
            </Badge>
            <CardTitle className="text-base text-slate-800">{module.title}</CardTitle>
          </div>
          {canDelete ? (
            <Button type="button" variant="outline" size="sm" className="border-rose-200 text-rose-700 hover:bg-rose-50 hover:text-rose-800" onClick={() => void handleDelete()} disabled={deleting || running}>
              <Trash2 className="h-4 w-4" />
              {deleting ? "删除中..." : "删除模块"}
            </Button>
          ) : null}
        </div>
        <CardDescription className="text-[13px] leading-relaxed">{module.summary}</CardDescription>
      </CardHeader>

      <CardContent className="space-y-4 pt-6">
        <div className="flex flex-wrap gap-2">
          {tags.map((tag) => (
            <Badge key={`${module.id}-${tag}`} variant="outline" className="border-slate-200 bg-slate-50 text-slate-700">
              {tag}
            </Badge>
          ))}
        </div>

        {hasSchemaForm ? (
          <>
            {module.formSchema?.description ? (
              <div className="rounded-xl border border-sky-100 bg-sky-50/70 px-4 py-3 text-[13px] leading-relaxed text-sky-800">
                {module.formSchema.description}
              </div>
            ) : null}

            <div className="grid gap-4">
              {module.formSchema?.fields.map((field) => (
                <Field key={`${module.id}-${field.name}`} label={field.label}>
                  {renderField(field, values[field.name] ?? "", (next) => {
                    setValues((current) => ({ ...current, [field.name]: next }));
                  }, running)}
                  {field.helpText ? <span className="text-xs leading-relaxed text-slate-500">{field.helpText}</span> : null}
                </Field>
              ))}
            </div>

            <div className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3">
              <div className="min-w-0 text-xs text-slate-500">
                调用入口: <span className="font-mono text-slate-700">{module.interfaceSchema?.invokePath}</span>
              </div>
              <Button type="button" onClick={() => void handleRun()} disabled={running}>
                {running ? "运行中..." : module.formSchema?.submitLabel ?? "运行模块"}
              </Button>
            </div>

            {error ? <ErrorBlock message={error} /> : null}

            {(resultText || resultJSON || resultTable) ? (
              <div className="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-sm font-semibold text-slate-800">{resultTitle}</div>
                {resultTable && resultTable.columns.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
                    <table className="min-w-full text-left text-xs text-slate-700">
                      <thead className="bg-slate-100 text-slate-800">
                        <tr>
                          {resultTable.columns.map((column) => (
                            <th key={`${module.id}-${column.key}`} className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold">
                              {column.label}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {resultTable.rows.map((row, index) => (
                          <tr key={`${module.id}-row-${index}`} className="border-b border-slate-100 last:border-b-0">
                            {resultTable.columns.map((column) => (
                              <td key={`${module.id}-${index}-${column.key}`} className="whitespace-pre-wrap px-3 py-2 align-top">
                                {row[column.key] ?? ""}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {resultText ? (
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-200 bg-white p-3 text-xs leading-relaxed text-slate-700">
                    {resultText}
                  </pre>
                ) : null}
                {resultJSON ? (
                  <pre className="max-h-72 overflow-auto rounded-lg border border-slate-200 bg-slate-950 p-3 text-xs leading-relaxed text-slate-100">
                    {resultJSON}
                  </pre>
                ) : null}
              </div>
            ) : null}
          </>
        ) : (
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-[13px] text-slate-600">
            <div className="font-semibold text-slate-800">已注册模块</div>
            <div className="mt-2 break-all">
              API 前缀: <span className="font-mono text-slate-700">{module.apiPrefix}</span>
            </div>
            {module.docsPath ? (
              <div className="mt-1 break-all">
                文档: <span className="font-mono text-slate-700">{module.docsPath}</span>
              </div>
            ) : null}
            <div className="mt-3 leading-relaxed">
              当前模块已经接入后端注册表。若需要完整交互界面，请为该模块补充 `form.json` 与 `api.json`，即可自动使用统一卡片模板。
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
