import { ShieldAlert } from "lucide-react";

import { yaraBinHint, yaraRulesHint } from "./RuntimeSettingsHints";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field } from "./RuntimeSettingsSidebarParts";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";
import { RuntimeToolStatusLine } from "./RuntimeToolStatusLine";

export function YaraSettingsSection(props: RuntimeSettingsSectionProps) {
  const { form, snapshot, setForm, unknownMessage, unknownStateText } = props;
  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={ShieldAlert} iconClassName="bg-amber-50 text-amber-600">
        YARA 狩猎
      </RuntimeSettingsSectionTitle>
      <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2.5">
        <div>
          <div className="text-xs font-semibold text-slate-800">启用 YARA 狩猎</div>
          <div className="mt-0.5 text-[11px] text-slate-500">
            关闭后会保留路径配置，只是不再参与对象与重组流内容的狩猎扫描。
          </div>
        </div>
        <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700">
          <input
            type="checkbox"
            checked={form.yaraEnabled}
            onChange={(event) => setForm((prev) => ({ ...prev, yaraEnabled: event.target.checked }))}
          />
          已启用
        </label>
      </div>
      <div className="grid grid-cols-1 gap-3">
        <Field
          label="显式配置：YARA 可执行路径"
          hint={yaraBinHint(snapshot, form.yaraBin)}
          value={form.yaraBin}
          onChange={(value) => setForm((prev) => ({ ...prev, yaraBin: value }))}
          placeholder="C:\\tools\\yara64.exe"
        />
        <Field
          label="显式配置：YARA 规则文件"
          hint={yaraRulesHint(snapshot, form.yaraRules)}
          value={form.yaraRules}
          onChange={(value) => setForm((prev) => ({ ...prev, yaraRules: value }))}
          placeholder="C:\\rules\\default.yar 或 C:\\rules\\traffic-pack\\"
        />
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-slate-700">YARA 超时（毫秒）</span>
          <input
            type="number"
            min={1000}
            step={1000}
            value={form.yaraTimeoutMs}
            onChange={(event) => setForm((prev) => ({ ...prev, yaraTimeoutMs: Number(event.target.value) || 25000 }))}
            className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none transition focus:border-blue-400"
          />
        </label>
      </div>
      <RuntimeToolStatusLine
        label="YARA"
        status={snapshot?.yara}
        enabled={snapshot?.yara.enabled ?? form.yaraEnabled}
        known={Boolean(snapshot)}
        unknownMessage={unknownMessage}
        unknownStateText={unknownStateText}
      />
      {snapshot?.yara.rulePath ? (
        <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px] leading-5 text-slate-500">
          当前使用的规则文件：
          <span className="break-all text-slate-700"> {snapshot.yara.rulePath}</span>
        </div>
      ) : null}
      {snapshot?.yara.lastScanMessage ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-5 text-amber-700">
          最近一次扫描告警：
          <span className="break-all"> {snapshot.yara.lastScanMessage}</span>
        </div>
      ) : null}
    </RuntimeSettingsSectionShell>
  );
}
