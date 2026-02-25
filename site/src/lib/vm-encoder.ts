import { rotl32, rotr32, swap32, setBit } from "./bitwise";
import { readU32LE, readU32BE, writeU32LE, writeU32BE } from "./encoding";
import { applySbox } from "./sbox";
import { toHex, fromHex } from "./encoding";
import { crc32, adler32, xorChecksum } from "./checksum";

export interface BytecodesForEncoder {
  vm: number[];
  vm_inv: number[];
  opcode_action: number[];
}

export interface EncoderOperation {
  op: number;
  params: number[];
}

function xorWithKey(buf: Uint8Array, key: Uint8Array): void {
  if (key.length === 0) return;
  for (let i = 0; i < buf.length; i++) buf[i]! ^= key[i % key.length]!;
}

function applyInverseOp(
  idx: number,
  buf: Uint8Array,
  params: number[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  const vm = new Uint8Array(bytecodes.vm);
  const vmInv = new Uint8Array(bytecodes.vm_inv);
  const key = params.length > 0 ? new Uint8Array(params) : new Uint8Array(0);

  switch (idx) {
    case 0:
      return applySbox(buf, vmInv, true);
    case 1:
      return applySbox(buf, vm, true);
    case 2:
    case 3:
      xorWithKey(buf, key);
      return buf;
    case 4:
      if (buf.length >= 4) {
        writeU32BE(crc32(buf.subarray(0, buf.length - 4)), buf, buf.length - 4);
      }
      return buf;
    case 5:
      if (buf.length >= 4) {
        writeU32BE(adler32(buf.subarray(0, buf.length - 4)), buf, buf.length - 4);
      }
      return buf;
    case 6:
      if (buf.length >= 1) {
        buf[buf.length - 1] = xorChecksum(buf.subarray(0, buf.length - 1));
      }
      return buf;
    case 7: {
      const hexStr = toHex(buf);
      return new TextEncoder().encode(hexStr);
    }
    case 8: {
      const hexStr = new TextDecoder().decode(buf);
      return fromHex(hexStr);
    }
    case 9:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32BE(buf, k);
        writeU32LE(v, buf, k);
      }
      return buf;
    case 10:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32LE(buf, k);
        writeU32BE(v, buf, k);
      }
      return buf;
    case 11:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32LE(buf, k);
        writeU32BE(v, buf, k);
      }
      return buf;
    case 12:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32BE(buf, k);
        writeU32LE(v, buf, k);
      }
      return buf;
    case 13:
      if (key.length > 0) {
        const r = key[0]! & 31;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(rotr32(v, r) >>> 0, buf, k);
        }
      }
      return buf;
    case 14:
      if (key.length > 0) {
        const r = key[0]! & 31;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(rotl32(v, r) >>> 0, buf, k);
        }
      }
      return buf;
    case 15:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32LE(buf, k);
        writeU32LE(swap32(v) >>> 0, buf, k);
      }
      return buf;
    case 16:
      return buf;
    case 17:
      if (key.length >= 2) {
        const bi = key[0]! & 31;
        const on = key[1]! & 1;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(setBit(v, bi, on === 0) >>> 0, buf, k);
        }
      }
      return buf;
    case 18:
      throw new Error("vm-encoder: chacha_decrypt inverse (chacha_encrypt) not implemented");
    default:
      return buf;
  }
}

function applyForwardOp(
  idx: number,
  buf: Uint8Array,
  params: number[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  const vm = new Uint8Array(bytecodes.vm);
  const vmInv = new Uint8Array(bytecodes.vm_inv);
  const key = params.length > 0 ? new Uint8Array(params) : new Uint8Array(0);

  switch (idx) {
    case 0:
      return applySbox(buf, vm, true);
    case 1:
      return applySbox(buf, vmInv, true);
    case 2:
    case 3:
      xorWithKey(buf, key);
      return buf;
    case 4:
      if (buf.length >= 4) {
        writeU32BE(crc32(buf.subarray(0, buf.length - 4)), buf, buf.length - 4);
      }
      return buf;
    case 5:
      if (buf.length >= 4) {
        writeU32BE(adler32(buf.subarray(0, buf.length - 4)), buf, buf.length - 4);
      }
      return buf;
    case 6:
      if (buf.length >= 1) {
        buf[buf.length - 1] = xorChecksum(buf.subarray(0, buf.length - 1));
      }
      return buf;
    case 7: {
      const hexStr = toHex(buf);
      return new TextEncoder().encode(hexStr);
    }
    case 8: {
      const hexStr = new TextDecoder().decode(buf);
      return fromHex(hexStr);
    }
    case 9:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32BE(buf, k);
        writeU32LE(v, buf, k);
      }
      return buf;
    case 10:
    case 11:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32LE(buf, k);
        writeU32BE(v, buf, k);
      }
      return buf;
    case 12:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32BE(buf, k);
        writeU32LE(v, buf, k);
      }
      return buf;
    case 13:
      if (key.length > 0) {
        const r = key[0]! & 31;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(rotl32(v, r) >>> 0, buf, k);
        }
      }
      return buf;
    case 14:
      if (key.length > 0) {
        const r = key[0]! & 31;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(rotr32(v, r) >>> 0, buf, k);
        }
      }
      return buf;
    case 15:
      for (let k = 0; k + 4 <= buf.length; k += 4) {
        const v = readU32LE(buf, k);
        writeU32LE(swap32(v) >>> 0, buf, k);
      }
      return buf;
    case 16:
      return buf;
    case 17:
      if (key.length >= 2) {
        const bi = key[0]! & 31;
        const on = key[1]! & 1;
        for (let k = 0; k + 4 <= buf.length; k += 4) {
          const v = readU32LE(buf, k);
          writeU32LE(setBit(v, bi, on !== 0) >>> 0, buf, k);
        }
      }
      return buf;
    case 18:
      throw new Error("vm-encoder: chacha_decrypt not supported in run");
    default:
      return buf;
  }
}

export function run(
  buffer: Uint8Array,
  operations: EncoderOperation[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  const opcodeAction = bytecodes.opcode_action;
  let buf = new Uint8Array(buffer);

  for (let i = 0; i < operations.length; i++) {
    const { op, params } = operations[i]!;
    const idx = op <= 255 ? opcodeAction[op] : 255;
    if (idx === 255) continue;

    buf = new Uint8Array(applyForwardOp(idx, buf, params, bytecodes));
  }

  return buf;
}

export function encode(
  plaintext: Uint8Array,
  operations: EncoderOperation[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  const opcodeAction = bytecodes.opcode_action;
  let buf = new Uint8Array(plaintext);

  for (let i = operations.length - 1; i >= 0; i--) {
    const { op, params } = operations[i]!;
    const idx = op <= 255 ? opcodeAction[op] : 255;
    if (idx === 255) continue;

    buf = new Uint8Array(applyInverseOp(idx, buf, params, bytecodes));
  }

  return buf;
}
