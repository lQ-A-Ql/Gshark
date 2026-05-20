export type RawStreamTone = {
  clientBadge: string;
  clientCard: string;
  serverBadge: string;
  serverCard: string;
};

export const TCP_RAW_STREAM_TONE: RawStreamTone = {
  clientBadge: "border-rose-200/30 bg-rose-50/20 text-rose-700",
  clientCard: "border-rose-500/30 bg-rose-500/10 text-rose-700",
  serverBadge: "border-blue-200/30 bg-blue-50/20 text-blue-700",
  serverCard: "border-blue-500/30 bg-blue-500/10 text-blue-700",
};

export const UDP_RAW_STREAM_TONE: RawStreamTone = {
  clientBadge: "border-amber-200/30 bg-amber-50/20 text-amber-700",
  clientCard: "border-amber-500/30 bg-amber-500/10 text-amber-700",
  serverBadge: "border-cyan-200/30 bg-cyan-50/20 text-cyan-700",
  serverCard: "border-cyan-500/30 bg-cyan-500/10 text-cyan-700",
};
