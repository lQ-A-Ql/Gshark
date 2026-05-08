import { Input } from "../../components/ui/input";
import type { MiscModuleFormField } from "../../core/types";
import { Field } from "../ui";
import { GenericMiscSelectField, miscFieldSurfaceClass } from "./GenericMiscSelectField";

export function buildInitialValues(fields: MiscModuleFormField[] = []): Record<string, string> {
  return fields.reduce<Record<string, string>>((acc, field) => {
    acc[field.name] = field.defaultValue ?? "";
    return acc;
  }, {});
}

function renderField(field: MiscModuleFormField, value: string, onChange: (next: string) => void, disabled: boolean) {
  const commonClass = "border-slate-200 bg-white text-slate-900";
  if (field.type === "textarea") {
    return (
      <textarea
        value={value}
        disabled={disabled}
        rows={field.rows ?? 6}
        placeholder={field.placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={`min-h-[140px] w-full resize-y rounded-2xl border px-4 py-3 text-sm leading-relaxed outline-none ${miscFieldSurfaceClass}`}
      />
    );
  }
  if (field.type === "select") {
    return <GenericMiscSelectField field={field} value={value} onChange={onChange} disabled={disabled} />;
  }
  return (
    <Input
      value={value}
      disabled={disabled}
      type={field.secret ? "password" : field.type === "number" ? "number" : "text"}
      placeholder={field.placeholder}
      onChange={(event) => onChange(event.target.value)}
      className={`h-11 rounded-xl px-3.5 text-sm ${commonClass} ${miscFieldSurfaceClass}`}
    />
  );
}

interface GenericMiscFormFieldsProps {
  moduleId: string;
  fields: MiscModuleFormField[];
  values: Record<string, string>;
  running: boolean;
  onValueChange: (fieldName: string, value: string) => void;
}

export function GenericMiscFormFields({
  moduleId,
  fields,
  values,
  running,
  onValueChange,
}: GenericMiscFormFieldsProps) {
  return (
    <div className="grid gap-4 rounded-2xl border border-slate-100 bg-white/80 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_12px_30px_rgba(15,23,42,0.04)]">
      {fields.map((field) => (
        <Field key={`${moduleId}-${field.name}`} label={field.label}>
          {renderField(
            field,
            values[field.name] ?? "",
            (next) => {
              onValueChange(field.name, next);
            },
            running,
          )}
          {field.helpText ? (
            <span className="rounded-lg bg-slate-50 px-2.5 py-1.5 text-xs leading-relaxed text-slate-500">
              {field.helpText}
            </span>
          ) : null}
        </Field>
      ))}
    </div>
  );
}
