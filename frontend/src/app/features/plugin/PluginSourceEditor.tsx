import { useEffect, useRef, useState } from "react";
import { Code2, Save, X } from "lucide-react";
import type { PluginSource } from "../../integrations/mappers/pluginSourceMapper";

interface PluginSourceEditorProps {
  source: PluginSource;
  loading: boolean;
  onSave: (source: PluginSource) => Promise<void>;
  onClose: () => void;
}

export function PluginSourceEditor({ source, loading, onSave, onClose }: PluginSourceEditorProps) {
  const [configContent, setConfigContent] = useState(source.configContent);
  const [logicContent, setLogicContent] = useState(source.logicContent);
  const [saveError, setSaveError] = useState("");
  const [dirty, setDirty] = useState(false);
  const firstTextareaRef = useRef<HTMLTextAreaElement>(null);
  const sourceRef = useRef(source);
  const initialConfigRef = useRef(source.configContent);
  const initialLogicRef = useRef(source.logicContent);

  // Sync source prop changes
  useEffect(() => {
    if (
      source.configContent !== sourceRef.current.configContent ||
      source.logicContent !== sourceRef.current.logicContent
    ) {
      sourceRef.current = source;
      initialConfigRef.current = source.configContent;
      initialLogicRef.current = source.logicContent;
      setConfigContent(source.configContent);
      setLogicContent(source.logicContent);
      setSaveError("");
      setDirty(false);
    }
  }, [source.configContent, source.logicContent]);

  // Focus trap: focus first textarea on mount
  useEffect(() => {
    firstTextareaRef.current?.focus();
  }, []);

  // Escape key to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (dirty && !window.confirm("有未保存的更改，确定关闭吗？")) return;
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose, dirty]);

  // Mark background as inert
  useEffect(() => {
    const mainContent = document.querySelector("[data-page-shell]");
    if (mainContent) mainContent.setAttribute("aria-hidden", "true");
    return () => {
      if (mainContent) mainContent.removeAttribute("aria-hidden");
    };
  }, []);

  const handleConfigChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setConfigContent(e.target.value);
    setDirty(true);
    if (saveError) setSaveError("");
  };

  const handleLogicChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setLogicContent(e.target.value);
    setDirty(true);
    if (saveError) setSaveError("");
  };

  const handleClose = () => {
    if (dirty && !window.confirm("有未保存的更改，确定关闭吗？")) return;
    onClose();
  };

  const handleSave = async () => {
    setSaveError("");
    try {
      await onSave({
        ...source,
        configContent,
        logicContent,
      });
    } catch {
      setSaveError("保存失败");
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={handleClose}
    >
      <div
        className="gshark-tile flex max-h-[80vh] w-full max-w-4xl flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="gshark-tile-header flex items-center gap-2 px-4 py-3">
          <Code2 className="h-4 w-4 text-indigo-600" />
          <span className="text-sm font-medium text-slate-700">编辑插件源码 — {source.id}</span>
          {dirty && <span className="text-xs text-amber-500">（未保存）</span>}
          <button
            type="button"
            onClick={handleClose}
            className="ml-auto p-1 text-slate-400 hover:text-slate-600"
            aria-label="关闭编辑器"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex flex-1 flex-col gap-4 overflow-auto p-4">
          {/* Config section */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-600">配置文件</span>
              <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-400">
                {source.configPath || "config.json"}
              </span>
            </div>
            <textarea
              ref={firstTextareaRef}
              value={configContent}
              onChange={handleConfigChange}
              className="h-48 resize-y border border-slate-200 bg-slate-50/50 p-3 font-mono text-xs text-slate-700 outline-none focus:border-indigo-300"
              spellCheck={false}
              placeholder='{ "name": "my-plugin", "version": "1.0.0" }'
              maxLength={100000}
            />
          </div>

          {/* Logic section */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-600">逻辑代码</span>
              <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-400">
                {source.logicPath || "plugin.js"}
              </span>
            </div>
            <textarea
              value={logicContent}
              onChange={handleLogicChange}
              className="h-64 resize-y border border-slate-200 bg-slate-50/50 p-3 font-mono text-xs text-slate-700 outline-none focus:border-indigo-300"
              spellCheck={false}
              placeholder="// plugin.js&#10;function onPacket(packet, ctx) {&#10;  // your detection logic&#10;}"
              maxLength={100000}
            />
          </div>

          {saveError && <div className="text-xs text-rose-600">{saveError}</div>}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-[var(--gshark-tile-divider)] px-4 py-3">
          <button
            type="button"
            onClick={handleClose}
            className="border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-50"
          >
            取消
          </button>
          <button
            type="button"
            onClick={() => void handleSave()}
            disabled={loading}
            className="flex items-center gap-1.5 border border-indigo-300 bg-indigo-50 px-3 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100 disabled:opacity-50"
          >
            <Save className="h-3 w-3" />
            {loading ? "保存中..." : "保存"}
          </button>
        </div>
      </div>
    </div>
  );
}
