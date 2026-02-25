export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, "");
  if (clean.length % 2 !== 0) throw new Error("Invalid hex: odd length");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (isNaN(byte)) throw new Error("Invalid hex character");
    bytes[i] = byte;
  }
  return bytes;
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes)    .toString("base64");
}

export function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const b64Padded = pad ? padded + "=".repeat(4 - pad) : padded;
  return new Uint8Array(Buffer.from(b64Padded, "base64"));
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function toBase32(bytes: Uint8Array): string {
  let result = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

export function fromBase32(b32: string): Uint8Array {
  const clean = b32.replace(/=+$/, "").toUpperCase();
  const chars = clean.split("").map((c) => {
    const idx = BASE32_ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`Invalid base32 character: ${c}`);
    return idx;
  });
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const v of chars) {
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function readU32BE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset]! << 24) |
    (bytes[offset + 1]! << 16) |
    (bytes[offset + 2]! << 8) |
    bytes[offset + 3]!
  );
}

export function writeU32BE(value: number, out: Uint8Array, offset: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

export function readU32LE(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset]! |
    (bytes[offset + 1]! << 8) |
    (bytes[offset + 2]! << 16) |
    (bytes[offset + 3]! << 24)
  );
}

export function writeU32LE(value: number, out: Uint8Array, offset: number): void {
  out[offset] = value & 0xff;
  out[offset + 1] = (value >>> 8) & 0xff;
  out[offset + 2] = (value >>> 16) & 0xff;
  out[offset + 3] = (value >>> 24) & 0xff;
}

export function readU64BE(bytes: Uint8Array, offset: number): bigint {
  const hi = readU32BE(bytes, offset);
  const lo = readU32BE(bytes, offset + 4);
  return (BigInt(hi) << 32n) | BigInt(lo);
}

export function writeU64BE(value: bigint, out: Uint8Array, offset: number): void {
  writeU32BE(Number((value >> 32n) & 0xffffffffn), out, offset);
  writeU32BE(Number(value & 0xffffffffn), out, offset + 4);
}

export function readU64LE(bytes: Uint8Array, offset: number): bigint {
  const lo = readU32LE(bytes, offset);
  const hi = readU32LE(bytes, offset + 4);
  return (BigInt(hi) << 32n) | BigInt(lo);
}

export function writeU64LE(value: bigint, out: Uint8Array, offset: number): void {
  writeU32LE(Number(value & 0xffffffffn), out, offset);
  writeU32LE(Number((value >> 32n) & 0xffffffffn), out, offset + 4);
}

export function encodeVarint(value: number | bigint): Uint8Array {
  const out: number[] = [];
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n) throw new Error("Varint must be non-negative");
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return new Uint8Array(out);
}

export function decodeVarint(bytes: Uint8Array, offset = 0): { value: bigint; bytesRead: number } {
  let value = 0n;
  let shift = 0n;
  let i = offset;
  while (i < bytes.length) {
    const byte = bytes[i]!;
    value |= BigInt(byte & 0x7f) << shift;
    i++;
    if ((byte & 0x80) === 0) return { value, bytesRead: i - offset };
    shift += 7n;
    if (shift > 63n) throw new Error("Varint overflow");
  }
  throw new Error("Varint truncated");
}
