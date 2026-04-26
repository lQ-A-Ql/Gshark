import { Check, ChevronDown, Loader2, Play, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import type { MiscModuleFormField, MiscModuleTableResult } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import type { MiscModuleRendererProps } from "../types";
import { ErrorBlock, Field } from "../ui";

const fieldSurfaceClass =
  "border-slate-200/80 bg-gradient-to-br from-white to-slate-50/80 text-slate-900 shadow-[0_1px_0_rgba(15,23,42,0.03),0_10px_24px_rgba(15,23,42,0.04)] transition-all placeholder:text-slate-400 hover:border-cyan-200 hover:bg-white focus:border-cyan-400 focus:bg-white focus:ring-4 focus:ring-cyan-100/70 disabled:cursor-not-allowed disabled:opacity-60";

function SchemaSelectField({
  field,
  value,
  onChange,
  disabled,
}: {
  field: MiscModuleFormField;
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [rendered, setRendered] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | undefined>(undefined);
  const options = field.options ?? [];
  const selected = options.find((option) => option.value === value);
  const placeholder = field.placeholder ?? "请选择";
  const displayText = selected?.label || placeholder;
  const allOptions = [{ label: placeholder, value: "" }, ...options];

  const clearCloseTimer = () => {
    if (closeTimerRef.current !== undefined) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = undefined;
    }
  };

  const openDropdown = () => {
    clearCloseTimer();
    setRendered(true);
    setOpen(true);
  };

  const closeDropdown = () => {
    clearCloseTimer();
    setOpen(false);
    closeTimerRef.current = window.setTimeout(() => {
      setRendered(false);
      closeTimerRef.current = undefined;
    }, 170);
  };

  useEffect(() => () => clearCloseTimer(), []);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const handlePointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        closeDropdown();
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeDropdown();
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (disabled) {
      closeDropdown();
    }
  }, [disabled]);

  return (
    <div ref={rootRef} className="relative">
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={(event) => {
          event.preventDefault();
          if (!disabled) {
            if (open) {
              closeDropdown();
            } else {
              openDropdown();
            }
          }
        }}
        onKeyDown={(event) => {
          if (disabled) {
            return;
          }
          if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
            event.preventDefault();
            openDropdown();
          }
        }}
        className={`flex h-11 w-full cursor-pointer items-center justify-between gap-3 rounded-xl border px-3.5 text-sm outline-none ${fieldSurfaceClass} ${
          open ? "border-cyan-400 bg-white ring-4 ring-cyan-100/70" : ""
        } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
      >
        <span className={`min-w-0 truncate ${selected ? "text-slate-900" : "text-slate-400"}`}>{displayText}</span>
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200 ${open ? "rotate-180 text-cyan-500" : ""}`} />
      </div>

      {rendered ? (
        <div
          role="listbox"
          className={`absolute left-0 right-0 top-full z-50 mt-2 origin-top overflow-hidden rounded-2xl border border-cyan-100 bg-white/95 p-1.5 shadow-[0_22px_55px_rgba(8,145,178,0.18)] ring-1 ring-cyan-50 backdrop-blur ${
            open
              ? "animate-[misc-select-panel-in_180ms_cubic-bezier(0.22,1,0.36,1)_both]"
              : "pointer-events-none animate-[misc-select-panel-out_160ms_cubic-bezier(0.4,0,1,1)_both]"
          }`}
        >
          <div
            className={`pointer-events-none absolute inset-x-0 top-0 h-12 bg-gradient-to-b from-transparent via-cyan-200/35 to-transparent ${
              open
                ? "animate-[misc-select-stream_820ms_cubic-bezier(0.22,1,0.36,1)_both]"
                : "animate-[misc-select-stream-out_160ms_cubic-bezier(0.4,0,1,1)_both]"
            }`}
          />
          <div className="max-h-64 overflow-auto pr-1">
            {allOptions.map((option, index) => {
              const active = option.value === value;
              return (
                <button
                  key={`${field.name}-${option.value || "__empty"}`}
                  type="button"
                  role="option"
                  aria-selected={active}
                  onClick={(event) => {
                    event.preventDefault();
                    onChange(option.value);
                    closeDropdown();
                  }}
                  style={{ animationDelay: open ? `${Math.min(index * 24, 144)}ms` : "0ms" }}
                  className={`group relative flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left text-sm transition-colors ${
                    open
                      ? "animate-[misc-select-option-in_220ms_cubic-bezier(0.22,1,0.36,1)_both]"
                      : "animate-[misc-select-option-out_120ms_cubic-bezier(0.4,0,1,1)_both]"
                  } ${
                    active
                      ? "bg-gradient-to-r from-cyan-50 to-sky-50 font-semibold text-cyan-800"
                      : "text-slate-700 hover:bg-slate-50 hover:text-cyan-700"
                  }`}
                >
                  <span className="min-w-0 truncate">{option.label || option.value || placeholder}</span>
                  {active ? <Check className="h-4 w-4 shrink-0 text-cyan-500" /> : null}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}

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
        className={`min-h-[140px] w-full resize-y rounded-2xl border px-4 py-3 text-sm leading-relaxed outline-none ${fieldSurfaceClass}`}
      />
    );
  }
  if (field.type === "select") {
    return <SchemaSelectField field={field} value={value} onChange={onChange} disabled={disabled} />;
  }
  return (
    <Input
      value={value}
      disabled={disabled}
      type={field.secret ? "password" : field.type === "number" ? "number" : "text"}
      placeholder={field.placeholder}
      onChange={(event) => onChange(event.target.value)}
      className={`h-11 rounded-xl px-3.5 text-sm ${commonClass} ${fieldSurfaceClass}`}
    />
  );
}

export function GenericMiscModule({ module, onModuleDeleted, surfaceVariant = "card" }: MiscModuleRendererProps) {
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
    <div className={embedded ? "space-y-5" : "space-y-5 rounded-b-xl bg-gradient-to-b from-white via-white to-slate-50/80 pt-6"}>
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
            {module.formSchema?.description ? <div className="text-[13px] leading-relaxed text-slate-600">{module.formSchema.description}</div> : null}
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
          <Badge key={`${module.id}-${tag}`} variant="outline" className="rounded-full border-cyan-100 bg-cyan-50/70 px-2.5 py-1 text-[11px] font-semibold text-cyan-800 shadow-sm">
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
          title={module.cancellable ? "该模块的分析请求支持中途取消或切换时自动中断" : "该模块当前按同步请求执行，没有单独的中断能力位"}
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

          <div className="grid gap-4 rounded-2xl border border-slate-100 bg-white/80 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_12px_30px_rgba(15,23,42,0.04)]">
            {module.formSchema?.fields.map((field) => (
              <Field key={`${module.id}-${field.name}`} label={field.label}>
                {renderField(field, values[field.name] ?? "", (next) => {
                  setValues((current) => ({ ...current, [field.name]: next }));
                }, running)}
                {field.helpText ? <span className="rounded-lg bg-slate-50 px-2.5 py-1.5 text-xs leading-relaxed text-slate-500">{field.helpText}</span> : null}
              </Field>
            ))}
          </div>

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
              {running ? "运行中..." : module.formSchema?.submitLabel ?? "运行模块"}
            </Button>
          </div>

          {error ? <ErrorBlock message={error} /> : null}

          {(resultText || resultJSON || resultTable) ? (
            <div className="space-y-3 rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-4 shadow-[0_14px_36px_rgba(15,23,42,0.06)]">
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm font-semibold text-slate-800">{resultTitle}</div>
                <Badge variant="outline" className="rounded-full border-emerald-100 bg-emerald-50 text-[11px] text-emerald-700">
                  Result
                </Badge>
              </div>
              {resultTable && resultTable.columns.length > 0 ? (
                <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
                  <table className="min-w-full text-left text-xs text-slate-700">
                    <thead className="bg-gradient-to-r from-slate-100 to-cyan-50 text-slate-800">
                      <tr>
                        {resultTable.columns.map((column) => (
                          <th key={`${module.id}-${column.key}`} className="whitespace-nowrap border-b border-slate-200 px-3 py-2.5 font-semibold">
                            {column.label}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {resultTable.rows.map((row, index) => (
                        <tr key={`${module.id}-row-${index}`} className="border-b border-slate-100 transition-colors last:border-b-0 hover:bg-cyan-50/40">
                          {resultTable.columns.map((column) => (
                            <td key={`${module.id}-${index}-${column.key}`} className="whitespace-pre-wrap px-3 py-2.5 align-top">
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
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-white p-3.5 text-xs leading-relaxed text-slate-700 shadow-inner">
                  {resultText}
                </pre>
              ) : null}
              {resultJSON ? (
                <pre className="max-h-72 overflow-auto rounded-xl border border-slate-800 bg-[linear-gradient(135deg,#020617_0%,#0f172a_58%,#111827_100%)] p-3.5 text-xs leading-relaxed text-cyan-50 shadow-inner">
                  {resultJSON}
                </pre>
              ) : null}
            </div>
          ) : null}
        </>
      ) : (
        <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-4 text-[13px] text-slate-600 shadow-inner">
          <div className="font-semibold text-slate-800">已注册模块</div>
          <div className="mt-2 break-all">
            API 前缀: <span className="rounded bg-white px-1.5 py-0.5 font-mono text-slate-700 shadow-sm">{module.apiPrefix}</span>
          </div>
          {module.docsPath ? (
            <div className="mt-1 break-all">
              文档: <span className="rounded bg-white px-1.5 py-0.5 font-mono text-slate-700 shadow-sm">{module.docsPath}</span>
            </div>
          ) : null}
          <div className="mt-3 leading-relaxed">
            当前模块已经接入后端注册表。若需要完整交互界面，请为该模块补充 `form.json` 与 `api.json`，即可自动使用统一卡片模板。
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
      <CardHeader className="relative gap-3 rounded-t-xl border-b border-cyan-100/70 bg-[radial-gradient(circle_at_12%_20%,rgba(34,211,238,0.22),transparent_34%),linear-gradient(135deg,#0f172a_0%,#164e63_58%,#1e3a8a_100%)] pb-5 text-white">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="border-white/20 bg-white/12 text-white shadow-sm backdrop-blur">
                {module.kind === "custom" ? "Custom" : "Builtin"}
              </Badge>
              {module.interfaceSchema?.runtime ? (
                <Badge variant="outline" className="border-cyan-200/40 bg-cyan-300/15 text-cyan-50 shadow-sm backdrop-blur">
                  {module.interfaceSchema.runtime}
                </Badge>
              ) : null}
            </div>
            <CardTitle className="break-words text-lg font-semibold tracking-tight text-white drop-shadow-sm">{module.title}</CardTitle>
          </div>
          {canDelete ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-white/20 bg-white/10 text-white shadow-sm backdrop-blur hover:border-rose-200/60 hover:bg-rose-500/20 hover:text-white"
              onClick={() => void handleDelete()}
              disabled={deleting || running}
            >
              {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              {deleting ? "删除中..." : "删除模块"}
            </Button>
          ) : null}
        </div>
        <CardDescription className="max-w-3xl text-[13px] leading-relaxed text-cyan-50/85">{module.summary}</CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  );
}
