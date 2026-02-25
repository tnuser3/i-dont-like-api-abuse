export function xorInPlace(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error("XOR: buffers must be same length");
  for (let i = 0; i < a.length; i++) a[i]! ^= b[i]!;
  return a;
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  if (a.length !== b.length) throw new Error("XOR: buffers must be same length");
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

export function rotl32(value: number, n: number): number {
  n &= 31;
  return ((value << n) | (value >>> (32 - n))) >>> 0;
}

export function rotr32(value: number, n: number): number {
  n &= 31;
  return ((value >>> n) | (value << (32 - n))) >>> 0;
}

export function rotl64(value: bigint, n: number): bigint {
  n &= 63;
  const mask = (1n << 64n) - 1n;
  return ((value << BigInt(n)) | (value >> BigInt(64 - n))) & mask;
}

export function rotr64(value: bigint, n: number): bigint {
  n &= 63;
  const mask = (1n << 64n) - 1n;
  return ((value >> BigInt(n)) | (value << BigInt(64 - n))) & mask;
}

export function swap32(value: number): number {
  return (
    ((value & 0xff) << 24) |
    ((value & 0xff00) << 8) |
    ((value & 0xff0000) >> 8) |
    ((value & 0xff000000) >>> 24)
  );
}

export function getBit(value: number, bit: number): number {
  return (value >>> bit) & 1;
}

export function setBit(value: number, bit: number, on: boolean): number {
  return on ? value | (1 << bit) : value & ~(1 << bit);
}

export function clz32(value: number): number {
  if (value === 0) return 32;
  let n = 0;
  if ((value & 0xffff0000) === 0) {
    n += 16;
    value <<= 16;
  }
  if ((value & 0xff000000) === 0) {
    n += 8;
    value <<= 8;
  }
  if ((value & 0xf0000000) === 0) {
    n += 4;
    value <<= 4;
  }
  if ((value & 0xc0000000) === 0) {
    n += 2;
    value <<= 2;
  }
  if ((value & 0x80000000) === 0) n += 1;
  return n;
}

export function ctz32(value: number): number {
  if (value === 0) return 32;
  let n = 0;
  if ((value & 0x0000ffff) === 0) {
    n += 16;
    value >>>= 16;
  }
  if ((value & 0x000000ff) === 0) {
    n += 8;
    value >>>= 8;
  }
  if ((value & 0x0000000f) === 0) {
    n += 4;
    value >>>= 4;
  }
  if ((value & 0x00000003) === 0) {
    n += 2;
    value >>>= 2;
  }
  if ((value & 0x00000001) === 0) n += 1;
  return n;
}

export function popcount32(value: number): number {
  value -= (value >>> 1) & 0x55555555;
  value = (value & 0x33333333) + ((value >>> 2) & 0x33333333);
  value = (value + (value >>> 4)) & 0x0f0f0f0f;
  return (value * 0x01010101) >>> 24;
}
