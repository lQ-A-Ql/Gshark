export interface MiscModuleFieldOptionWireDTO extends Record<string, unknown> {
  value?: unknown;
  label?: unknown;
}

export interface MiscModuleFormFieldWireDTO extends Record<string, unknown> {
  name?: unknown;
  label?: unknown;
  type?: unknown;
  placeholder?: unknown;
  default_value?: unknown;
  help_text?: unknown;
  required?: unknown;
  secret?: unknown;
  rows?: unknown;
  options?: MiscModuleFieldOptionWireDTO[];
}

export interface MiscModuleFormSchemaWireDTO extends Record<string, unknown> {
  description?: unknown;
  submit_label?: unknown;
  result_title?: unknown;
  fields?: MiscModuleFormFieldWireDTO[];
}

export interface MiscModuleInterfaceSchemaWireDTO extends Record<string, unknown> {
  method?: unknown;
  invoke_path?: unknown;
  runtime?: unknown;
  entry?: unknown;
  host_bridge?: unknown;
}

export interface MiscModuleManifestWireDTO extends Record<string, unknown> {
  id?: unknown;
  kind?: unknown;
  title?: unknown;
  summary?: unknown;
  tags?: unknown;
  api_prefix?: unknown;
  docs_path?: unknown;
  requires_capture?: unknown;
  protocol_domain?: unknown;
  supports_export?: unknown;
  cancellable?: unknown;
  depends_on?: unknown;
  form_schema?: MiscModuleFormSchemaWireDTO;
  interface_schema?: MiscModuleInterfaceSchemaWireDTO;
}

export interface MiscModuleImportResultWireDTO extends Record<string, unknown> {
  module?: MiscModuleManifestWireDTO;
  installed_path?: unknown;
  message?: unknown;
}

export interface MiscModuleRunResultWireDTO extends Record<string, unknown> {
  message?: unknown;
  text?: unknown;
  output?: unknown;
  table?: unknown;
}
