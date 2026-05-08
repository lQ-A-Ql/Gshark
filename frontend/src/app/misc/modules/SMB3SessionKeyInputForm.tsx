import { Input } from "../../components/ui/input";
import { Field } from "../ui";

interface SMB3SessionKeyInputFormProps {
  domain: string;
  encryptedSessionKey: string;
  ntProofStr: string;
  ntlmHash: string;
  onDomainChange: (value: string) => void;
  onEncryptedSessionKeyChange: (value: string) => void;
  onNtProofStrChange: (value: string) => void;
  onNtlmHashChange: (value: string) => void;
  onUsernameChange: (value: string) => void;
  username: string;
}

export function SMB3SessionKeyInputForm({
  domain,
  encryptedSessionKey,
  ntProofStr,
  ntlmHash,
  onDomainChange,
  onEncryptedSessionKeyChange,
  onNtProofStrChange,
  onNtlmHashChange,
  onUsernameChange,
  username,
}: SMB3SessionKeyInputFormProps) {
  return (
    <>
      <Field label="Username (用户名)">
        <Input
          value={username}
          onChange={(event) => onUsernameChange(event.target.value)}
          className="font-mono text-sm shadow-sm"
          placeholder="Administrator"
        />
      </Field>
      <Field label="Domain (域名/可留空)">
        <Input
          value={domain}
          onChange={(event) => onDomainChange(event.target.value)}
          className="font-mono text-sm shadow-sm"
          placeholder="WORKGROUP 或留空"
        />
      </Field>
      <Field label="NTLM Hash (十六进制)">
        <Input
          value={ntlmHash}
          onChange={(event) => onNtlmHashChange(event.target.value)}
          className="font-mono text-sm shadow-sm"
          placeholder="例如: 31d...89c0"
        />
      </Field>
      <div className="grid grid-cols-2 gap-4">
        <Field label="NTProofStr">
          <Input
            value={ntProofStr}
            onChange={(event) => onNtProofStrChange(event.target.value)}
            className="font-mono text-sm shadow-sm"
            placeholder="..."
          />
        </Field>
        <Field label="Encrypted Session Key">
          <Input
            value={encryptedSessionKey}
            onChange={(event) => onEncryptedSessionKeyChange(event.target.value)}
            className="font-mono text-sm shadow-sm"
            placeholder="..."
          />
        </Field>
      </div>
    </>
  );
}
