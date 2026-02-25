export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  const table = getCrc32Table();
  for (let i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ bytes[i]!) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

let _crc32Table: Uint32Array | null = null;

function getCrc32Table(): Uint32Array {
  if (_crc32Table) return _crc32Table;
  const table = new Uint32Array(256);
  const poly = 0xedb88320;
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (c >>> 1) ^ poly : c >>> 1;
    table[i] = c >>> 0;
  }
  _crc32Table = table;
  return table;
}

export function crc32WithInit(bytes: Uint8Array, init: number): number {
  let crc = init ^ 0xffffffff;
  const table = getCrc32Table();
  for (let i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ bytes[i]!) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function adler32(bytes: Uint8Array): number {
  const mod = 65521;
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]!) % mod;
    b = (b + a) % mod;
  }
  return ((b << 16) | a) >>> 0;
}

export function fletcher16(bytes: Uint8Array): number {
  let sum1 = 0;
  let sum2 = 0;
  for (let i = 0; i < bytes.length; i++) {
    sum1 = (sum1 + bytes[i]!) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return (sum2 << 8) | sum1;
}

export function fletcher32(bytes: Uint8Array): number {
  const mod = 0xffff;
  let sum1 = 0;
  let sum2 = 0;
  for (let i = 0; i < bytes.length; i += 2) {
    const word = i + 1 < bytes.length
      ? (bytes[i]! << 8) | bytes[i + 1]!
      : bytes[i]! << 8;
    sum1 = (sum1 + word) % mod;
    sum2 = (sum2 + sum1) % mod;
  }
  return (sum2 << 16) | sum1;
}

export function xorChecksum(bytes: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < bytes.length; i++) sum ^= bytes[i]!;
  return sum & 0xff;
}

export function sum16(bytes: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) {
    const word = i + 1 < bytes.length
      ? (bytes[i]! << 8) | bytes[i + 1]!
      : bytes[i]! << 8;
    sum = (sum + word) >>> 0;
  }
  return sum & 0xffff;
}
