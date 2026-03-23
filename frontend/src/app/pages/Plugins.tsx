import Editor, { type BeforeMount } from "@monaco-editor/react";
import { useMemo, useRef, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Download,
  FileCode2,
  FileJson,
  Puzzle,
  RefreshCw,
  Save,
  Search,
  Terminal,
  ToggleLeft,
  ToggleRight,
  Upload,
  XCircle,
} from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useSentinel } from "../state/SentinelContext";
import { bridge } from "../integrations/wailsBridge";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

type StatusFilter = "all" | "enabled" | "disabled";
type RuntimeOption = "javascript" | "python";
type SourceTab = "logic" | "json";

const JS_TEMPLATE = (pluginId: string) => `export function onPacket(packet, ctx) {
  const info = String(packet.info || "");
  const payload = String(packet.payload || "");
  const text = info + "\\n" + payload;

  if (text.includes("flag{") || text.includes("ctf{")) {
    ctx.emitHit({
      category: "CTF",
      rule: "${pluginId}-flag-detect",
      level: "high",
      packetId: packet.id,
      preview: text.slice(0, 120),
      match: "flag"
    });
  }
}

export function onFinish(ctx) {
  ctx.log("${pluginId} finished");
}
`;

const PY_TEMPLATE = (pluginId: string) => `import json
import sys

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    packet = json.loads(raw)
    text = str(packet.get("info", "")) + "\\n" + str(packet.get("payload", ""))
    if "flag{" in text or "ctf{" in text:
        sys.stdout.write(json.dumps({
            "packetId": packet.get("id"),
            "category": "CTF",
            "rule": "${pluginId}-flag-detect",
            "level": "high",
            "preview": text[:120],
            "match": "flag"
        }) + "\\n")
        sys.stdout.flush()
`;

const editorOptions = {
  automaticLayout: true,
  fontSize: 12,
  lineNumbersMinChars: 3,
  minimap: { enabled: false },
  padding: { top: 12, bottom: 12 },
  scrollBeyondLastLine: false,
  tabSize: 2,
  wordWrap: "on" as const,
};

const configureJsonDiagnostics: BeforeMount = (monaco) => {
  monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
    validate: true,
    allowComments: false,
    trailingCommas: "error",
    schemaValidation: "warning",
    schemas: [
      {
        uri: "inmemory://gshark/plugin-config.schema.json",
        fileMatch: ["*"],
        schema: {
          type: "object",
          properties: {
            id: { type: "string" },
            name: { type: "string" },
            version: { type: "string" },
            tag: { type: "string" },
            author: { type: "string" },
            enabled: { type: "boolean" },
            entry: { type: "string" },
            runtime: { type: "string" },
          },
          required: ["id", "name", "version", "tag", "author", "enabled"],
          additionalProperties: true,
        },
      },
    ],
  });
};

function detectLogicLanguage(entry: string, logicPath: string) {
  const target = `${entry} ${logicPath}`.toLowerCase();
  if (target.includes(".py")) return "python";
  if (target.includes(".ts")) return "typescript";
  if (target.includes(".mjs") || target.includes(".cjs") || target.includes(".js")) return "javascript";
  return "plaintext";
}

function buildDefaultConfig(pluginId: string, runtime: RuntimeOption, entry: string) {
  return JSON.stringify(
    {
      id: pluginId,
      name: pluginId,
      version: "1.0.0",
      tag: "custom",
      author: "analyst",
      enabled: true,
      entry,
      runtime,
    },
    null,
    2,
  );
}

export default function Plugins() {
  const { plugins, togglePlugin, pluginLogs, setPluginsEnabled, refreshPlugins, addPlugin, deletePlugin } = useSentinel();
  const [search, setSearch] = useState("");
  const [tagFilter, setTagFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [newVersion, setNewVersion] = useState("1.0.0");
  const [newTag, setNewTag] = useState("custom");
  const [newAuthor, setNewAuthor] = useState("analyst");
  const [newRuntime, setNewRuntime] = useState<RuntimeOption>("python");
  const [newEntry, setNewEntry] = useState("");
  const [addHint, setAddHint] = useState("");

  const [sourcePluginId, setSourcePluginId] = useState("");
  const [sourceConfigPath, setSourceConfigPath] = useState("");
  const [sourceConfigCode, setSourceConfigCode] = useState("");
  const [sourceLogicPath, setSourceLogicPath] = useState("");
  const [sourceLogicCode, setSourceLogicCode] = useState("");
  const [sourceEntry, setSourceEntry] = useState("");
  const [sourceTab, setSourceTab] = useState<SourceTab>("logic");
  const [sourceLoading, setSourceLoading] = useState(false);
  const [sourceSaving, setSourceSaving] = useState(false);
  const [sourceError, setSourceError] = useState("");
  const [sourceNotice, setSourceNotice] = useState("");

  const tags = useMemo(() => ["all", ...Array.from(new Set(plugins.map((p) => p.tag)))], [plugins]);
  const selectedIds = useMemo(() => Array.from(selected), [selected]);
  const enabledCount = useMemo(() => plugins.filter((plugin) => plugin.enabled).length, [plugins]);
  const disabledCount = plugins.length - enabledCount;

  const filtered = useMemo(() => {
    return plugins.filter((plugin) => {
      if (search.trim()) {
        const query = search.trim().toLowerCase();
        if (
          !plugin.name.toLowerCase().includes(query) &&
          !String(plugin.id).toLowerCase().includes(query) &&
          !(plugin.entry || "").toLowerCase().includes(query)
        ) {
          return false;
        }
      }
      if (tagFilter !== "all" && plugin.tag !== tagFilter) return false;
      if (statusFilter === "enabled" && !plugin.enabled) return false;
      if (statusFilter === "disabled" && plugin.enabled) return false;
      return true;
    });
  }, [plugins, search, statusFilter, tagFilter]);

  const sourceConfigValidationError = useMemo(() => {
    const raw = sourceConfigCode.trim();
    if (!raw) return "";
    try {
      JSON.parse(raw);
      return "";
    } catch (error) {
      return error instanceof Error ? error.message : "Invalid JSON";
    }
  }, [sourceConfigCode]);

  const sourceLogicLanguage = useMemo(
    () => detectLogicLanguage(sourceEntry, sourceLogicPath),
    [sourceEntry, sourceLogicPath],
  );

  const toggleSelected = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleAddPlugin = async () => {
    const ts = Date.now();
    const id = newId.trim() || `custom-${ts}`;
    const name = newName.trim() || `Custom Plugin ${ts}`;
    const runtime = newRuntime;
    const entry = newEntry.trim() || (runtime === "python" ? `${id}.py` : `${id}.js`);

    try {
      await addPlugin({
        id,
        name,
        version: newVersion.trim() || "1.0.0",
        tag: newTag.trim() || "custom",
        author: newAuthor.trim() || "analyst",
        enabled: true,
        entry,
        runtime,
      });
      setAddHint(`Plugin created: ${name} (${entry})`);
      setNewId(`custom-${ts + 1}`);
      setNewName("");
      setNewEntry("");
      refreshPlugins();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to add plugin";
      setAddHint(`Add failed: ${message}`);
    }
  };

  const handleViewSource = async (id: string) => {
    setSourcePluginId(id);
    setSourceLoading(true);
    setSourceSaving(false);
    setSourceError("");
    setSourceNotice("");
    try {
      const source = await bridge.getPluginSource(id);
      setSourceConfigPath(source.configPath);
      setSourceConfigCode(source.configContent || "");
      setSourceLogicPath(source.logicPath);
      setSourceLogicCode(source.logicContent || "");
      setSourceEntry(source.entry || "");
      setSourceTab(source.logicContent ? "logic" : "json");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load plugin source";
      setSourceError(message);
      setSourceConfigPath("");
      setSourceConfigCode("");
      setSourceLogicPath("");
      setSourceLogicCode("");
      setSourceEntry("");
    } finally {
      setSourceLoading(false);
    }
  };

  const applySourceTemplate = (runtime: RuntimeOption) => {
    const pluginId = sourcePluginId || newId.trim() || "custom-plugin";
    const entry = runtime === "python" ? `${pluginId}.py` : `${pluginId}.js`;
    setSourceEntry(entry);
    setSourceLogicCode(runtime === "python" ? PY_TEMPLATE(pluginId) : JS_TEMPLATE(pluginId));
    if (!sourceConfigCode.trim()) {
      setSourceConfigCode(buildDefaultConfig(pluginId, runtime, entry));
    }
    setSourceTab("logic");
    setSourceNotice(`${runtime === "python" ? "Python" : "JavaScript"} template applied`);
  };

  const handleSaveSource = async () => {
    if (!sourcePluginId) return;
    if (sourceConfigValidationError) {
      setSourceError(`Config JSON is invalid: ${sourceConfigValidationError}`);
      setSourceTab("json");
      return;
    }

    setSourceSaving(true);
    setSourceError("");
    setSourceNotice("");
    try {
      const saved = await bridge.savePluginSource({
        id: sourcePluginId,
        configPath: sourceConfigPath,
        configContent: sourceConfigCode,
        logicPath: sourceLogicPath,
        logicContent: sourceLogicCode,
        entry: sourceEntry,
      });
      setSourceConfigPath(saved.configPath);
      setSourceConfigCode(saved.configContent || "");
      setSourceLogicPath(saved.logicPath);
      setSourceLogicCode(saved.logicContent || "");
      setSourceEntry(saved.entry);
      setSourceNotice("Plugin source saved");
      refreshPlugins();
    } catch (error) {
      setSourceError(error instanceof Error ? error.message : "Failed to save plugin source");
    } finally {
      setSourceSaving(false);
    }
  };

  const fileInputRef = useRef<HTMLInputElement>(null);

  const downloadTemplate = (runtime: "javascript" | "python") => {
    const pluginId = "sample-plugin";
    const content = runtime === "python" ? PY_TEMPLATE(pluginId) : JS_TEMPLATE(pluginId);
    const filename = runtime === "python" ? "plugin.py" : "plugin.js";
    const configContent = buildDefaultConfig(pluginId, runtime, filename);

    // Download logic file
    const logicBlob = new Blob([content], { type: "text/plain" });
    const logicUrl = URL.createObjectURL(logicBlob);
    const logicLink = document.createElement("a");
    logicLink.href = logicUrl;
    logicLink.download = filename;
    logicLink.click();
    URL.revokeObjectURL(logicUrl);

    // Download config file
    setTimeout(() => {
      const configBlob = new Blob([configContent], { type: "application/json" });
      const configUrl = URL.createObjectURL(configBlob);
      const configLink = document.createElement("a");
      configLink.href = configUrl;
      configLink.download = "plugin.json";
      configLink.click();
      URL.revokeObjectURL(configUrl);
    }, 100);
  };

  const handleImportPlugin = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const fileArray = Array.from(files);
    let configFile: File | null = null;
    let logicFile: File | null = null;

    for (const file of fileArray) {
      if (file.name.endsWith(".json")) {
        configFile = file;
      } else if (file.name.endsWith(".js") || file.name.endsWith(".py") || file.name.endsWith(".ts")) {
        logicFile = file;
      }
    }

    if (!configFile && !logicFile) {
      setAddHint("Please select a .json config file and/or a .js/.py/.ts logic file");
      return;
    }

    try {
      let configContent = "";
      let logicContent = "";
      let pluginId = `imported-${Date.now()}`;
      let pluginName = "Imported Plugin";
      let runtime: RuntimeOption = "javascript";
      let entry = "";

      if (configFile) {
        configContent = await configFile.text();
        try {
          const config = JSON.parse(configContent);
          pluginId = config.id || pluginId;
          pluginName = config.name || pluginName;
          runtime = config.runtime || runtime;
          entry = config.entry || entry;
        } catch {
          setAddHint("Invalid JSON config file");
          return;
        }
      }

      if (logicFile) {
        logicContent = await logicFile.text();
        entry = entry || logicFile.name;
        runtime = logicFile.name.endsWith(".py") ? "python" : "javascript";
      }

      if (!configContent) {
        configContent = buildDefaultConfig(pluginId, runtime, entry);
      }

      await addPlugin({
        id: pluginId,
        name: pluginName,
        version: "1.0.0",
        tag: "imported",
        author: "user",
        enabled: true,
        entry,
        runtime,
      });

      setAddHint(`Plugin imported: ${pluginName}`);
      refreshPlugins();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to import plugin";
      setAddHint(`Import failed: ${message}`);
    }

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-background text-sm text-foreground">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-5 py-3.5">
        <div className="flex items-center gap-3 text-lg font-semibold text-foreground">
          <Puzzle className="h-5 w-5 text-indigo-600" /> Plugin Manager
        </div>
        <div className="flex items-center gap-2">
          <button
            className="inline-flex items-center gap-1 rounded-md border border-indigo-300 bg-indigo-50 px-3 py-1.5 text-xs text-indigo-700 shadow-sm hover:bg-indigo-100"
            onClick={() => downloadTemplate("javascript")}
          >
            <Download className="h-3.5 w-3.5" /> JS Template
          </button>
          <button
            className="inline-flex items-center gap-1 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs text-emerald-700 shadow-sm hover:bg-emerald-100"
            onClick={() => downloadTemplate("python")}
          >
            <Download className="h-3.5 w-3.5" /> Py Template
          </button>
          <button
            className="inline-flex items-center gap-1 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 shadow-sm hover:bg-amber-100"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="h-3.5 w-3.5" /> Import Plugin
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,.js,.py,.ts"
            multiple
            onChange={handleImportPlugin}
            className="hidden"
          />
          <div className="mx-1 h-6 w-px bg-border" />
          <button
            className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm hover:bg-accent"
            onClick={refreshPlugins}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
          <button
            className="inline-flex items-center gap-1 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs text-emerald-700 shadow-sm hover:bg-emerald-100"
            onClick={() => setPluginsEnabled(selectedIds, true)}
            disabled={selectedIds.length === 0}
          >
            Enable Selected
          </button>
          <button
            className="inline-flex items-center gap-1 rounded-md border border-rose-300 bg-rose-50 px-3 py-1.5 text-xs text-rose-700 shadow-sm hover:bg-rose-100"
            onClick={() => setPluginsEnabled(selectedIds, false)}
            disabled={selectedIds.length === 0}
          >
            Disable Selected
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col bg-card">
          <div className="z-10 flex shrink-0 flex-col gap-3 border-b border-border bg-accent/40 p-3 shadow-sm">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="flex w-64 items-center gap-2 rounded-md border border-border bg-background px-3 py-1.5 shadow-sm transition-all focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
                  <Search className="h-4 w-4 text-muted-foreground" />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    type="text"
                    placeholder="Search plugins..."
                    className="flex-1 border-none bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground"
                  />
                </div>
                <select
                  value={tagFilter}
                  onChange={(event) => setTagFilter(event.target.value)}
                  className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
                >
                  {tags.map((tag) => (
                    <option key={tag} value={tag}>
                      {tag === "all" ? "All tags" : tag}
                    </option>
                  ))}
                </select>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                  className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
                >
                  <option value="all">All status</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>

              <div className="flex items-center gap-3 text-xs font-medium text-muted-foreground">
                <span className="flex items-center gap-1"><CheckCircle2 className="h-4 w-4 text-emerald-600" /> {enabledCount}</span>
                <span className="flex items-center gap-1"><XCircle className="h-4 w-4 text-rose-500" /> {disabledCount}</span>
                <span className="rounded bg-accent px-2 py-0.5 text-[10px] text-foreground">{selected.size} selected</span>
              </div>
            </div>

            <div className="grid grid-cols-8 gap-2">
              <input value={newId} onChange={(e) => setNewId(e.target.value)} placeholder="Plugin ID" className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground" />
              <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Plugin name" className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground" />
              <input value={newVersion} onChange={(e) => setNewVersion(e.target.value)} placeholder="Version" className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground" />
              <input value={newTag} onChange={(e) => setNewTag(e.target.value)} placeholder="Tag" className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground" />
              <input value={newAuthor} onChange={(e) => setNewAuthor(e.target.value)} placeholder="Author" className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground" />
              <select
                value={newRuntime}
                onChange={(e) => setNewRuntime(e.target.value as RuntimeOption)}
                className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
              >
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
              </select>
              <input
                value={newEntry}
                onChange={(e) => setNewEntry(e.target.value)}
                placeholder={newRuntime === "python" ? "Entry, e.g. demo.py" : "Entry, e.g. demo.js"}
                className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground"
              />
              <button
                className="rounded-md border border-blue-300 bg-blue-50 px-2 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100"
                onClick={() => void handleAddPlugin()}
              >
                Add Plugin
              </button>
            </div>
            {addHint && <div className="text-xs text-muted-foreground">{addHint}</div>}
          </div>

          <div className="flex flex-1 flex-col gap-3 overflow-auto p-5">
            {filtered.map((plugin) => {
              const checked = selected.has(String(plugin.id));
              return (
                <div
                  key={plugin.id}
                  className={cn(
                    "flex items-center justify-between rounded-xl border p-4 shadow-sm transition-all hover:shadow-md",
                    plugin.enabled ? "border-border bg-card" : "border-border/70 bg-accent/30 opacity-85 hover:opacity-100",
                  )}
                >
                  <div className="flex items-center gap-4">
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleSelected(String(plugin.id))}
                      className="h-4 w-4 accent-blue-600"
                    />
                    <div className="flex items-center justify-center rounded-lg border border-border bg-accent/40 p-2.5">
                      <Puzzle className={cn("h-6 w-6", plugin.enabled ? "text-indigo-600" : "text-slate-400")} />
                    </div>

                    <div>
                      <div className="flex items-center gap-2.5 text-sm font-semibold text-foreground">
                        {plugin.name}
                        <span className="rounded-md border border-border bg-accent px-2 py-0.5 text-[10px] font-bold tracking-wide text-muted-foreground">{plugin.tag}</span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-4 text-xs font-medium text-muted-foreground">
                        <span>v{plugin.version}</span>
                        <span className="flex items-center gap-1"><FileJson className="h-3.5 w-3.5" /> {plugin.author}</span>
                        {plugin.runtime && <span>{plugin.runtime}</span>}
                        {plugin.entry && <span className="font-mono">{plugin.entry}</span>}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button className="flex items-center gap-3" onClick={() => togglePlugin(plugin.id)}>
                      <span className={cn("w-10 text-right text-xs font-bold", plugin.enabled ? "text-emerald-600" : "text-muted-foreground")}>
                        {plugin.enabled ? "On" : "Off"}
                      </span>
                      {plugin.enabled ? <ToggleRight className="h-8 w-8 text-indigo-600" /> : <ToggleLeft className="h-8 w-8 text-slate-300" />}
                    </button>
                    <button
                      className="rounded-md border border-rose-300 bg-rose-50 px-2 py-1 text-xs font-medium text-rose-700 hover:bg-rose-100"
                      onClick={() => void deletePlugin(plugin.id)}
                    >
                      Delete
                    </button>
                    <button
                      className="rounded-md border border-blue-300 bg-blue-50 px-2 py-1 text-xs font-medium text-blue-700 hover:bg-blue-100"
                      onClick={() => void handleViewSource(String(plugin.id))}
                    >
                      Open Source
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="z-10 flex w-[560px] shrink-0 flex-col border-l border-border bg-[#111111] shadow-lg">
          <div className="flex items-center gap-2 border-b border-slate-800 bg-[#0b0b0b] px-4 py-3 text-xs font-bold uppercase tracking-wider text-slate-400">
            <Terminal className="h-4 w-4 text-emerald-500" /> Source Editor and Logs
          </div>

          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="border-b border-slate-800 p-4">
              <div className="mb-3 flex flex-wrap items-center gap-2 text-[10px] text-slate-400">
                <span>Plugin {sourcePluginId || "-"}</span>
                {sourceConfigValidationError && <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-amber-300">JSON invalid</span>}
              </div>

              {sourceLoading ? (
                <div className="rounded border border-slate-700 bg-[#171717] px-3 py-4 text-sm text-slate-400">Loading source...</div>
              ) : sourceError && !sourcePluginId ? (
                <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-4 text-sm text-amber-300">{sourceError}</div>
              ) : sourcePluginId ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      className={cn("rounded border px-2 py-1 text-xs", sourceTab === "logic" ? "border-blue-500 text-blue-300" : "border-slate-600 text-slate-400")}
                      onClick={() => setSourceTab("logic")}
                    >
                      Logic
                    </button>
                    <button
                      className={cn("rounded border px-2 py-1 text-xs", sourceTab === "json" ? "border-blue-500 text-blue-300" : "border-slate-600 text-slate-400")}
                      onClick={() => setSourceTab("json")}
                    >
                      Config JSON
                    </button>
                    <button className="rounded border border-emerald-500 px-2 py-1 text-xs text-emerald-300" onClick={() => applySourceTemplate("python")}>
                      Python Template
                    </button>
                    <button className="rounded border border-indigo-500 px-2 py-1 text-xs text-indigo-300" onClick={() => applySourceTemplate("javascript")}>
                      JS Template
                    </button>
                    <button
                      className="inline-flex items-center gap-1 rounded border border-blue-500 px-2 py-1 text-xs text-blue-300 disabled:border-slate-700 disabled:text-slate-500"
                      onClick={() => void handleSaveSource()}
                      disabled={sourceSaving || Boolean(sourceConfigValidationError)}
                    >
                      <Save className="h-3 w-3" /> {sourceSaving ? "Saving..." : "Save"}
                    </button>
                  </div>

                  <input
                    value={sourceEntry}
                    onChange={(event) => setSourceEntry(event.target.value)}
                    placeholder="Entry file, e.g. sample.py"
                    className="w-full rounded border border-slate-700 bg-[#171717] px-3 py-2 text-xs text-slate-200 outline-none"
                  />

                  {sourceNotice && <div className="text-xs text-emerald-400">{sourceNotice}</div>}
                  {sourceError && <div className="text-xs text-amber-300">{sourceError}</div>}
                  {sourceConfigValidationError && (
                    <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
                      Config JSON error: {sourceConfigValidationError}
                    </div>
                  )}

                  {sourceTab === "logic" ? (
                    <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#171717]">
                      <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-2 text-[11px] text-slate-400">
                        <FileCode2 className="h-3.5 w-3.5" />
                        <span className="truncate">{sourceLogicPath || "(new logic file)"}</span>
                        <span className="ml-auto uppercase">{sourceLogicLanguage}</span>
                      </div>
                      <Editor
                        beforeMount={configureJsonDiagnostics}
                        height="360px"
                        language={sourceLogicLanguage}
                        path={sourceLogicPath || `inmemory://gshark/${sourcePluginId}/${sourceEntry || "plugin.js"}`}
                        theme="vs-dark"
                        value={sourceLogicCode}
                        onChange={(value) => setSourceLogicCode(value ?? "")}
                        options={editorOptions}
                      />
                    </div>
                  ) : (
                    <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#171717]">
                      <div className="flex items-center gap-2 border-b border-slate-800 px-3 py-2 text-[11px] text-slate-400">
                        <FileJson className="h-3.5 w-3.5" />
                        <span className="truncate">{sourceConfigPath || "(generated config)"}</span>
                        <span className="ml-auto uppercase">json</span>
                      </div>
                      <Editor
                        beforeMount={configureJsonDiagnostics}
                        height="360px"
                        language="json"
                        path={sourceConfigPath || `inmemory://gshark/${sourcePluginId}/plugin.json`}
                        theme="vs-dark"
                        value={sourceConfigCode}
                        onChange={(value) => setSourceConfigCode(value ?? "")}
                        options={editorOptions}
                      />
                    </div>
                  )}
                </div>
              ) : (
                <div className="rounded border border-slate-700 bg-[#171717] px-3 py-4 text-sm text-slate-500">
                  Open a plugin to edit source code, switch templates, and save changes.
                </div>
              )}
            </div>

            <div className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed">
              <div className="mb-3 rounded border border-slate-700 bg-[#171717] p-3 text-[10px] text-slate-300">
                <div className="mb-1 text-slate-400">Templates</div>
                <div className="mb-2 text-slate-500">Python and JavaScript plugins both support packet-by-packet analysis.</div>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap text-[10px] leading-relaxed">{JS_TEMPLATE("demo-js")}</pre>
                <div className="mt-3" />
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap text-[10px] leading-relaxed">{PY_TEMPLATE("demo-py")}</pre>
              </div>

              {pluginLogs.map((log, index) => {
                let color = "text-slate-300";
                if (log.includes("[INFO]")) color = "text-emerald-400";
                if (log.includes("[WARN]")) color = "text-amber-400";
                if (log.includes("[DEBUG]")) color = "text-slate-500";
                return (
                  <div key={`${log}-${index}`} className={cn("mb-1.5 break-words", color)}>
                    {log}
                  </div>
                );
              })}

              <div className="mt-3 flex animate-pulse items-center gap-2 font-medium text-emerald-500/70">
                <Activity className="h-3.5 w-3.5" /> Listening for plugin logs...
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
