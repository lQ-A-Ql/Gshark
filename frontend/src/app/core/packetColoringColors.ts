export type RGB16 = [number, number, number];

export function parseRGB16Triplet(value: string): RGB16 {
  const parts = value.split(",").map((x) => Number(x.trim()));
  if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n))) {
    return [0, 0, 0];
  }
  return [parts[0], parts[1], parts[2]];
}

function rgb16To8Bit(value: number): number {
  return Math.max(0, Math.min(255, Math.round(value / 257)));
}

export function rgb16ToCss(color16: RGB16): string {
  const [r16, g16, b16] = color16;
  return `rgb(${rgb16To8Bit(r16)}, ${rgb16To8Bit(g16)}, ${rgb16To8Bit(b16)})`;
}

export function rgb16ToRgba(color16: RGB16, alpha: number): string {
  const [r16, g16, b16] = color16;
  const safeAlpha = Math.max(0, Math.min(1, alpha));
  return `rgba(${rgb16To8Bit(r16)}, ${rgb16To8Bit(g16)}, ${rgb16To8Bit(b16)}, ${safeAlpha})`;
}
