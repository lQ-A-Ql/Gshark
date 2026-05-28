import React, { useState } from "react";
import { Plus, Power, PowerOff, Trash2, Code2, CheckSquare, Square } from "lucide-react";
import { cn } from "../../components/ui/utils";
import type { PluginItem } from "../../core/types";

interface PluginManagerShellProps {
  plugins: PluginItem[];
  loading: boolean;
  error: string;
  onAdd: (input: { name: string; entry: string; version?: string; author?: string; tag?: string }) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onToggle: (id: string) => Promise<void>;
  onBulkToggle: (ids: string[], enabled: boolean) => Promise<void>;
  onOpenSource: (id: string) => void;
}

const MAX_NAME_LEN = 100;
const MAX_ENTRY_LEN = 200;

interface PluginRowProps {
  plugin: PluginItem;
  isSelected: boolean;
  onSelect: (id: string) => void;
  onOpenSource: (id: string) => void;
  onToggle: (id: string) => void;
  onDelete: (id: string, name: string) => void;
}

const PluginRow = React.memo(function PluginRow({
  plugin,
  isSelected,
  onSelect,
  onOpenSource,
  onToggle,
  onDelete,
}: PluginRowProps) {
  const id = String(plugin.id);
  return (
    <tr
      className={cn(
        "border-b border-[var(--gshark-tile-divider)] hover:bg-indigo-50/30",
        isSelected && "bg-indigo-50/50",
      )}
    >
      <td className="px-3 py-2">
        <button
          type="button"
          role="checkbox"
          aria-checked={isSelected}
          aria-label={`选择 ${plugin.name}`}
          onClick={() => onSelect(id)}
          className="text-slate-400 hover:text-slate-600"
        >
          {isSelected ? (
            <CheckSquare className="h-3.5 w-3.5 text-indigo-600" />
          ) : (
            <Square className="h-3.5 w-3.5" />
          )}
        </button>
      </td>
      <td className="px-3 py-2 font-medium text-slate-700">{plugin.name}</td>
      <td className="px-3 py-2 text-slate-500">{plugin.version}</td>
      <td className="px-3 py-2">
        <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-500">
          {plugin.runtime || "js"}
        </span>
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap gap-1">
          {(plugin.capabilities ?? []).map((cap) => (
            <span
              key={cap}
              className="rounded border border-indigo-100 bg-indigo-50/60 px-1.5 py-0.5 text-[10px] text-indigo-600"
            >
              {cap}
            </span>
          ))}
        </div>
      </td>
      <td className="px-3 py-2 text-center">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            plugin.enabled ? "bg-emerald-500" : "bg-slate-300",
          )}
        />
      </td>
      <td className="px-3 py-2 text-right">
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={() => onOpenSource(id)}
            className="border border-slate-200 bg-white p-1 text-slate-500 hover:bg-slate-50 hover:text-indigo-600"
            aria-label={`编辑 ${plugin.name} 源码`}
          >
            <Code2 className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => onToggle(id)}
            className={cn(
              "border p-1",
              plugin.enabled
                ? "border-amber-200 bg-amber-50/60 text-amber-600 hover:bg-amber-100"
                : "border-emerald-200 bg-emerald-50/60 text-emerald-600 hover:bg-emerald-100",
            )}
            aria-label={plugin.enabled ? `禁用 ${plugin.name}` : `启用 ${plugin.name}`}
          >
            {plugin.enabled ? <PowerOff className="h-3 w-3" /> : <Power className="h-3 w-3" />}
          </button>
          <button
            type="button"
            onClick={() => onDelete(id, plugin.name)}
            className="border border-rose-200 bg-white p-1 text-rose-500 hover:bg-rose-50"
            aria-label={`删除 ${plugin.name}`}
          >
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
      </td>
    </tr>
  );
});

export function PluginManagerShell({
  plugins,
  loading,
  error,
  onAdd,
  onDelete,
  onToggle,
  onBulkToggle,
  onOpenSource,
}: PluginManagerShellProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showAdd, setShowAdd] = useState(false);
  const [addName, setAddName] = useState("");
  const [addEntry, setAddEntry] = useState("");
  const [addVersion, setAddVersion] = useState("1.0.0");
  const [addAuthor, setAddAuthor] = useState("");
  const [addError, setAddError] = useState("");

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === plugins.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(plugins.map((p) => String(p.id))));
    }
  };

  const handleAdd = async () => {
    if (!addName.trim() || !addEntry.trim()) {
      setAddError("名称和入口文件为必填项");
      return;
    }
    if (addName.length > MAX_NAME_LEN) {
      setAddError(`名称不能超过 ${MAX_NAME_LEN} 个字符`);
      return;
    }
    if (addEntry.length > MAX_ENTRY_LEN) {
      setAddError(`入口文件路径不能超过 ${MAX_ENTRY_LEN} 个字符`);
      return;
    }
    setAddError("");
    try {
      await onAdd({ name: addName.trim(), entry: addEntry.trim(), version: addVersion, author: addAuthor });
      setShowAdd(false);
      setAddName("");
      setAddEntry("");
      setAddVersion("1.0.0");
      setAddAuthor("");
    } catch {
      setAddError("添加失败");
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (window.confirm(`确定删除插件 "${name}" 吗？`)) {
      try {
        await onDelete(id);
        setSelected((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      } catch {
        // Error already set by hook
      }
    }
  };

  const handleBulk = async (enabled: boolean) => {
    if (selected.size === 0) return;
    try {
      await onBulkToggle(Array.from(selected), enabled);
      setSelected(new Set());
    } catch {
      // Error already set by hook
    }
  };

  return (
    <>
      {/* Toolbar */}
      <div className="gshark-tile-toolbar flex flex-wrap items-center gap-2.5 px-3 py-2.5">
        <button
          type="button"
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 border border-indigo-200 bg-indigo-50/80 px-3 py-1.5 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
        >
          <Plus className="h-3.5 w-3.5" /> 添加插件
        </button>
        {selected.size > 0 && (
          <>
            <span className="text-xs text-slate-500">已选 {selected.size} 个</span>
            <button
              type="button"
              onClick={() => void handleBulk(true)}
              className="flex items-center gap-1 border border-emerald-200 bg-emerald-50/80 px-2.5 py-1.5 text-xs text-emerald-700 hover:bg-emerald-100"
            >
              <Power className="h-3 w-3" /> 批量启用
            </button>
            <button
              type="button"
              onClick={() => void handleBulk(false)}
              className="flex items-center gap-1 border border-amber-200 bg-amber-50/80 px-2.5 py-1.5 text-xs text-amber-700 hover:bg-amber-100"
            >
              <PowerOff className="h-3 w-3" /> 批量禁用
            </button>
          </>
        )}
        <span className="ml-auto text-xs text-slate-400">{plugins.length} 个插件</span>
      </div>

      {/* Error */}
      {error && (
        <div className="gshark-tile mb-3 border-amber-200 bg-amber-50/80 px-3 py-2.5 text-xs text-amber-700" role="alert">
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="gshark-tile mb-3 border-indigo-100 bg-indigo-50/60 px-3 py-2.5 text-xs text-slate-500">
          正在加载插件列表...
        </div>
      )}

      {/* Add dialog */}
      {showAdd && (
        <div className="gshark-tile mb-3 border-indigo-200 bg-indigo-50/40 p-4">
          <div className="mb-3 text-sm font-medium text-slate-700">添加新插件</div>
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">名称 *</span>
              <input
                value={addName}
                onChange={(e) => setAddName(e.target.value)}
                className="border border-slate-200 px-2 py-1 text-xs outline-none focus:border-indigo-300"
                placeholder="My Plugin"
                maxLength={MAX_NAME_LEN}
                aria-describedby={addError ? "add-error" : undefined}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">入口文件 *</span>
              <input
                value={addEntry}
                onChange={(e) => setAddEntry(e.target.value)}
                className="border border-slate-200 px-2 py-1 text-xs outline-none focus:border-indigo-300"
                placeholder="plugin.js"
                maxLength={MAX_ENTRY_LEN}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">版本</span>
              <input
                value={addVersion}
                onChange={(e) => setAddVersion(e.target.value)}
                className="border border-slate-200 px-2 py-1 text-xs outline-none focus:border-indigo-300"
                maxLength={20}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500">作者</span>
              <input
                value={addAuthor}
                onChange={(e) => setAddAuthor(e.target.value)}
                className="border border-slate-200 px-2 py-1 text-xs outline-none focus:border-indigo-300"
                maxLength={50}
              />
            </label>
          </div>
          {addError && (
            <div id="add-error" className="mt-2 text-xs text-rose-600" role="alert">
              {addError}
            </div>
          )}
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => void handleAdd()}
              className="border border-indigo-300 bg-indigo-50 px-3 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
            >
              添加
            </button>
            <button
              type="button"
              onClick={() => {
                setShowAdd(false);
                setAddError("");
              }}
              className="border border-slate-200 bg-white px-3 py-1 text-xs text-slate-600 hover:bg-slate-50"
            >
              取消
            </button>
          </div>
        </div>
      )}

      {/* Plugin table */}
      {!loading && plugins.length > 0 && (
        <div className="gshark-tile overflow-hidden">
          <table role="grid" className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--gshark-tile-divider)] bg-slate-50/60">
                <th className="w-10 px-3 py-2 text-left">
                  <button
                    type="button"
                    role="checkbox"
                    aria-checked={selected.size === plugins.length && plugins.length > 0}
                    aria-label="全选插件"
                    onClick={toggleAll}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    {selected.size === plugins.length ? (
                      <CheckSquare className="h-3.5 w-3.5" />
                    ) : (
                      <Square className="h-3.5 w-3.5" />
                    )}
                  </button>
                </th>
                <th className="px-3 py-2 text-left font-medium text-slate-600">名称</th>
                <th className="w-20 px-3 py-2 text-left font-medium text-slate-600">版本</th>
                <th className="w-16 px-3 py-2 text-left font-medium text-slate-600">运行时</th>
                <th className="px-3 py-2 text-left font-medium text-slate-600">能力</th>
                <th className="w-16 px-3 py-2 text-center font-medium text-slate-600">状态</th>
                <th className="w-36 px-3 py-2 text-right font-medium text-slate-600">操作</th>
              </tr>
            </thead>
            <tbody>
              {plugins.map((plugin) => (
                <PluginRow
                  key={String(plugin.id)}
                  plugin={plugin}
                  isSelected={selected.has(String(plugin.id))}
                  onSelect={toggleSelect}
                  onOpenSource={onOpenSource}
                  onToggle={onToggle}
                  onDelete={handleDelete}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty state */}
      {!loading && plugins.length === 0 && (
        <div className="gshark-tile flex flex-col items-center gap-2 py-12 text-center text-slate-400">
          <Code2 className="h-8 w-8" />
          <div className="text-sm">暂无插件</div>
          <div className="text-xs">点击"添加插件"创建第一个自定义检测插件</div>
        </div>
      )}
    </>
  );
}
