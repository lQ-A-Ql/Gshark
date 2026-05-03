export interface MiscModuleFieldOption {
  value: string;
  label: string;
}

export interface MiscModuleFormField {
  name: string;
  label: string;
  type: string;
  placeholder?: string;
  defaultValue?: string;
  helpText?: string;
  required?: boolean;
  secret?: boolean;
  rows?: number;
  options?: MiscModuleFieldOption[];
}

export interface MiscModuleFormSchema {
  description?: string;
  submitLabel?: string;
  resultTitle?: string;
  fields: MiscModuleFormField[];
}

export interface MiscModuleInterfaceSchema {
  method?: string;
  invokePath?: string;
  runtime?: string;
  entry?: string;
  hostBridge?: boolean;
}

export interface MiscModuleTableColumn {
  key: string;
  label: string;
}

export interface MiscModuleTableResult {
  columns: MiscModuleTableColumn[];
  rows: Record<string, string>[];
}

export interface MiscModuleManifest {
  id: string;
  kind: string;
  title: string;
  summary: string;
  tags: string[];
  apiPrefix: string;
  docsPath?: string;
  requiresCapture: boolean;
  protocolDomain?: string;
  supportsExport?: boolean;
  cancellable?: boolean;
  dependsOn?: string[];
  formSchema?: MiscModuleFormSchema;
  interfaceSchema?: MiscModuleInterfaceSchema;
}

export interface MiscModuleRunResult {
  message: string;
  text?: string;
  output?: unknown;
  table?: MiscModuleTableResult;
}

export interface MiscModuleImportResult {
  module: MiscModuleManifest;
  installedPath: string;
  message: string;
}
