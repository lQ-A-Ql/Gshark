// custom-1773809467552 logic template
// Called by plugin runtime if supported by backend executor.

export function onPacket(packet, ctx) {
	const info = String(packet.info || "");
	if (info.includes("flag{") || info.includes("ctf{")) {
		ctx.emitHit({
			category: "CTF",
			rule: "custom-1773809467552-flag-detect",
			level: "high",
			packetId: packet.id,
			preview: info.slice(0, 120),
		});
	}
}

export function onFinish(ctx) {
	ctx.log("custom-1773809467552 finished");
}
