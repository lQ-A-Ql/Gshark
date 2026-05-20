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
  const commonClass = "text-slate-900";
  if (field.type === "textarea") {
    return (
      <textarea
        value={value}
        disabled={disabled}
        rows={field.rows ?? 6}
        placeholder={field.placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={`min-h-[140px] w-full resize-y px-4 py-3 text-sm leading-relaxed outline-none ${miscFieldSurfaceClass}`}
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
      className={`h-11 px-3.5 text-sm ${commonClass} ${miscFieldSurfaceClass}`}
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
    <div className="gshark-form-surface grid gap-4 p-4">
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
            <span className="gshark-diffuse-chip px-2.5 py-1.5 text-xs leading-relaxed text-slate-500">
              {field.helpText}
            </span>
          ) : null}
        </Field>
      ))}
    </div>
  );
}
