package model

type AuditEntry struct {
	Time          string `json:"time"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Action        string `json:"action"`
	Risk          string `json:"risk"`
	Origin        string `json:"origin,omitempty"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
	Status        int    `json:"status"`
	Authenticated bool   `json:"authenticated"`
}

type MiscModuleFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type MiscModuleFormField struct {
	Name         string                  `json:"name"`
	Label        string                  `json:"label"`
	Type         string                  `json:"type"`
	Placeholder  string                  `json:"placeholder,omitempty"`
	DefaultValue string                  `json:"default_value,omitempty"`
	HelpText     string                  `json:"help_text,omitempty"`
	Required     bool                    `json:"required,omitempty"`
	Secret       bool                    `json:"secret,omitempty"`
	Rows         int                     `json:"rows,omitempty"`
	Options      []MiscModuleFieldOption `json:"options,omitempty"`
}

type MiscModuleFormSchema struct {
	Description string                `json:"description,omitempty"`
	SubmitLabel string                `json:"submit_label,omitempty"`
	ResultTitle string                `json:"result_title,omitempty"`
	Fields      []MiscModuleFormField `json:"fields,omitempty"`
}

type MiscModuleInterfaceSchema struct {
	Method      string   `json:"method,omitempty"`
	InvokePath  string   `json:"invoke_path,omitempty"`
	Runtime     string   `json:"runtime,omitempty"`
	Entry       string   `json:"entry,omitempty"`
	HostBridge  bool     `json:"host_bridge,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type MiscModuleTableColumn struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type MiscModuleTableResult struct {
	Columns []MiscModuleTableColumn `json:"columns,omitempty"`
	Rows    []map[string]string     `json:"rows,omitempty"`
}

type MiscModuleManifest struct {
	ID              string                     `json:"id"`
	Kind            string                     `json:"kind"`
	Title           string                     `json:"title"`
	Summary         string                     `json:"summary"`
	Tags            []string                   `json:"tags"`
	APIPrefix       string                     `json:"api_prefix"`
	DocsPath        string                     `json:"docs_path,omitempty"`
	RequiresCapture bool                       `json:"requires_capture"`
	ProtocolDomain  string                     `json:"protocol_domain,omitempty"`
	SupportsExport  bool                       `json:"supports_export,omitempty"`
	Cancellable     bool                       `json:"cancellable,omitempty"`
	DependsOn       []string                   `json:"depends_on,omitempty"`
	FormSchema      *MiscModuleFormSchema      `json:"form_schema,omitempty"`
	InterfaceSchema *MiscModuleInterfaceSchema `json:"interface_schema,omitempty"`
}

type MiscModuleRunRequest struct {
	Values map[string]string `json:"values"`
}

type MiscModuleRunResult struct {
	Message string `json:"message,omitempty"`
	Text    string `json:"text,omitempty"`
	// Output stays dynamic because MISC modules can return scalar, object, or list payloads.
	Output any                    `json:"output,omitempty"`
	Table  *MiscModuleTableResult `json:"table,omitempty"`
}

type MiscModulePackageManifest struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	Version         string   `json:"version,omitempty"`
	Author          string   `json:"author,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	RequiresCapture bool     `json:"requires_capture,omitempty"`
	Backend         string   `json:"backend,omitempty"`
	Form            string   `json:"form,omitempty"`
	API             string   `json:"api,omitempty"`
	Permissions     []string `json:"permissions,omitempty"`
}

type MiscModulePackageImportResult struct {
	Module        MiscModuleManifest `json:"module"`
	InstalledPath string             `json:"installed_path"`
	Message       string             `json:"message"`
}
