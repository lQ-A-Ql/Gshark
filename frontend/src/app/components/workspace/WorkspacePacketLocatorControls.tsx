type PacketLocatorControlsProps = {
  packetIdInput: string;
  onPacketIdInputChange: (value: string) => void;
  onLocatePacket: (packetId: number) => void;
  disabled: boolean;
};

export function PacketLocatorControls({
  packetIdInput,
  onPacketIdInputChange,
  onLocatePacket,
  disabled,
}: PacketLocatorControlsProps) {
  const locate = () => {
    const packetId = Number(packetIdInput);
    if (packetId > 0) {
      onLocatePacket(packetId);
    }
  };

  return (
    <div className="gshark-tile-toolbar flex items-center gap-1 px-2 py-1 text-xs">
      <input
        value={packetIdInput}
        onChange={(event) => onPacketIdInputChange(event.target.value.replace(/[^0-9]/g, ""))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            locate();
          }
        }}
        className="w-20 border-none bg-transparent text-center font-mono text-foreground outline-none"
        placeholder="分组号"
        disabled={disabled}
      />
      <button
        onClick={locate}
        disabled={disabled}
        className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
      >
        定位
      </button>
    </div>
  );
}
