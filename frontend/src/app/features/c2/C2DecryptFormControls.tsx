import { FileKey2, Info } from "lucide-react";
import type { ReactNode } from "react";
import { SelectField, type SelectOption } from "../../components/ui/select";
import type { C2DecryptRequest } from "../../core/types";

type VShellMode = NonNullable<NonNullable<C2DecryptRequest["vshell"]>["mode"]>;
type CSKeyMode = NonNullable<NonNullable<C2DecryptRequest["cs"]>["keyMode"]>;
type CSTransformMode = NonNullable<NonNullable<C2DecryptRequest["cs"]>["transformMode"]>;

export interface VShellDecryptFormProps {
  mode: VShellMode;
  salt: string;
  vkey: string;
  onModeChange: (mode: VShellMode) => void;
  onSaltChange: (value: string) => void;
  onVKeyChange: (value: string) => void;
}

export function VShellDecryptForm({
  mode,
  salt,
  vkey,
  onModeChange,
  onSaltChange,
  onVKeyChange,
}: VShellDecryptFormProps) {
  return (
    <div className="space-y-3">
      <LabeledInput label="vkey（验证用，可空）" value={vkey} onChange={onVKeyChange} placeholder="VerifyKey / VKey" />
      <LabeledInput label="salt（必填）" value={salt} onChange={onSaltChange} placeholder="qwe123qwe" />
      <LabeledSelect
        label="模式"
        value={mode}
        onChange={(value) => onModeChange(value as VShellMode)}
        options={[
          ["auto", "auto：三 KDF + GCM/CBC 自动尝试"],
          ["aes_gcm_md5_salt", "AES-GCM / 三 KDF"],
          ["aes_cbc_md5_salt", "AES-CBC / 三 KDF"],
        ]}
      />
    </div>
  );
}

export interface CSDecryptFormProps {
  aesKey: string;
  aesRand: string;
  hmacKey: string;
  keyMode: CSKeyMode;
  rsaPrivateKey: string;
  transformMode: CSTransformMode;
  onAESKeyChange: (value: string) => void;
  onAESRandChange: (value: string) => void;
  onHMACKeyChange: (value: string) => void;
  onKeyModeChange: (mode: CSKeyMode) => void;
  onRSAPrivateKeyChange: (value: string) => void;
  onTransformModeChange: (mode: CSTransformMode) => void;
}

export function CSDecryptForm({
  aesKey,
  aesRand,
  hmacKey,
  keyMode,
  rsaPrivateKey,
  transformMode,
  onAESKeyChange,
  onAESRandChange,
  onHMACKeyChange,
  onKeyModeChange,
  onRSAPrivateKeyChange,
  onTransformModeChange,
}: CSDecryptFormProps) {
  return (
    <div className="space-y-3">
      <RawKeyHint />
      <LabeledSelect
        label="Key material"
        value={keyMode}
        onChange={(value) => onKeyModeChange(value as CSKeyMode)}
        options={[
          ["aes_hmac", "AES/HMAC keys"],
          ["aes_rand", "Raw key / AES rand 派生"],
          ["rsa_private_key", "RSA private key 恢复 Raw key"],
        ]}
      />
      {keyMode === "aes_hmac" ? (
        <KeyModeHint icon="AES/HMAC">
          直接输入已知 session AES key/HMAC key。未填 HMAC key 时只能尝试 AES-CBC，结果会标记为 unverified。
        </KeyModeHint>
      ) : null}
      {keyMode === "aes_rand" ? (
        <KeyModeHint icon="Raw">
          输入 cs-decrypt-metadata.py 这类工具输出的 Raw key。后端会按 SHA256(Raw key) 派生 AES/HMAC，只解 POST 与 HTTP
          200 响应候选。
        </KeyModeHint>
      ) : null}
      {keyMode === "rsa_private_key" ? (
        <KeyModeHint icon="RSA">
          输入 TeamServer RSA private key PEM。后端会优先尝试 GET Cookie/URI metadata，恢复 Raw key 后再解任务/回传。
        </KeyModeHint>
      ) : null}
      {keyMode === "aes_hmac" && (
        <>
          <LabeledInput label="AES key" value={aesKey} onChange={onAESKeyChange} placeholder="hex / base64 / raw" />
          <LabeledInput
            label="HMAC key（可空）"
            value={hmacKey}
            onChange={onHMACKeyChange}
            placeholder="hex / base64 / raw"
          />
        </>
      )}
      {keyMode === "aes_rand" && (
        <LabeledInput
          label="Raw key / AES rand"
          value={aesRand}
          onChange={onAESRandChange}
          placeholder="16-byte hex / base64 / raw，例如 a4553a..."
        />
      )}
      {keyMode === "rsa_private_key" && <RSAPrivateKeyInput value={rsaPrivateKey} onChange={onRSAPrivateKeyChange} />}
      <LabeledSelect
        label="Transform"
        value={transformMode}
        onChange={(value) => onTransformModeChange(value as CSTransformMode)}
        options={[
          ["auto", "auto"],
          ["raw", "raw"],
          ["base64", "base64"],
          ["base64url", "base64url"],
          ["netbios", "netbios"],
          ["netbiosu", "netbiosu"],
        ]}
      />
    </div>
  );
}

function RawKeyHint() {
  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
      <div className="mb-1 flex items-center gap-1.5 font-semibold">
        <Info className="h-3.5 w-3.5" />
        Raw key 来源说明
      </div>
      <p>
        CS Raw key 通常不是从 PCAP 直接算出。PCAP 只能提供 GET Cookie/URI 中的 RSA-encrypted metadata；需要 TeamServer
        的 <span className="font-mono">.cobaltstrike.beacon_keys</span> 或 RSA private key 解 metadata 后恢复 Raw
        key，再派生 AES/HMAC 解 POST 与 200 response。
      </p>
    </div>
  );
}

function RSAPrivateKeyInput({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-semibold text-slate-600">RSA private key PEM</span>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="min-h-28 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] text-slate-700 outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-100"
        placeholder="-----BEGIN RSA PRIVATE KEY-----"
      />
    </label>
  );
}

function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-semibold text-slate-600">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-9 w-full rounded-xl border border-slate-200 bg-white px-3 font-mono text-[11px] text-slate-700 outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-100"
      />
    </label>
  );
}

function KeyModeHint({ icon, children }: { icon: string; children: ReactNode }) {
  return (
    <div className="flex gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600">
      <FileKey2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500" />
      <div>
        <span className="font-semibold text-slate-800">{icon}</span>：{children}
      </div>
    </div>
  );
}

function LabeledSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<[string, string]>;
}) {
  const selectOptions: SelectOption[] = options.map(([optionValue, optionLabel]) => ({
    value: optionValue,
    label: optionLabel,
  }));

  return (
    <SelectField
      label={label}
      value={value}
      onValueChange={onChange}
      options={selectOptions}
      tone="rose"
      labelClassName="text-slate-600"
    />
  );
}
