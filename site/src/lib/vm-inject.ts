import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

export const ACTION_NAMES = [
  "vm_apply",
  "vm_apply_inv",
  "xor_buf",
  "xor_inplace",
  "crc32",
  "adler32",
  "xor_checksum",
  "to_hex",
  "from_hex",
  "read_u32be",
  "write_u32be",
  "read_u32le",
  "write_u32le",
  "rotl32",
  "rotr32",
  "swap32",
  "get_bit",
  "set_bit",
  "chacha_decrypt",
] as const;

export type ActionName = (typeof ACTION_NAMES)[number];

let vmInstance: {
  vm_run: (
    buf: number,
    buf_len: number,
    actions: number,
    actions_len: number,
    key: number,
    key_len: number,
  ) => number;
  memory: WebAssembly.Memory;
} | null = null;

let opcodesByAction: Record<string, number> | null = null;

function chachaPolyDecrypt(
  memory: WebAssembly.Memory,
  out: number,
  outlenPtr: number,
  ciphertext: number,
  ctlen: number,
  keyPtr: number,
  ivPtr: number,
  tagPtr: number,
): number {
  const buf = new Uint8Array(memory.buffer);
  const key = buf.slice(keyPtr, keyPtr + 32);
  const iv = buf.slice(ivPtr, ivPtr + 12);
  const tag = buf.slice(tagPtr, tagPtr + 16);
  const ct = buf.slice(ciphertext, ciphertext + ctlen);

  const combined = new Uint8Array(ctlen + 16);
  combined.set(ct);
  combined.set(tag, ctlen);

  try {
    const chacha = chacha20poly1305(key, iv);
    const plaintext = chacha.decrypt(combined);

    const outBuf = new Uint8Array(memory.buffer, out, ctlen);
    outBuf.set(plaintext.subarray(0, ctlen));
    const view = new DataView(memory.buffer);
    view.setUint32(outlenPtr, plaintext.length, true);
    return 0;
  } catch {
    return -1;
  }
}

export async function loadVm(options?: {
  wasmUrl?: string;
  bytecodesUrl?: string;
  basePath?: string;
}): Promise<{ opcodesByAction: Record<string, number> }> {
  const base = options?.basePath ?? "";
  const wasmUrl = options?.wasmUrl ?? `${base}/crypto_utils.wasm`;
  const bytecodesUrl = options?.bytecodesUrl ?? `${base}/bytecodes.json`;

  const [wasmRes, bytecodesRes] = await Promise.all([
    fetch(wasmUrl),
    fetch(bytecodesUrl),
  ]);

  if (!wasmRes.ok) throw new Error(`Failed to fetch WASM: ${wasmRes.status}`);
  if (!bytecodesRes.ok) throw new Error(`Failed to fetch bytecodes: ${bytecodesRes.status}`);

  const wasmBuffer = await wasmRes.arrayBuffer();
  const bytecodes = (await bytecodesRes.json()) as { bytecodes: Record<string, string> };

  opcodesByAction = {};
  for (const [hex, action] of Object.entries(bytecodes.bytecodes)) {
    opcodesByAction[action] = parseInt(hex, 16);
  }

  const memoryRef: { current: WebAssembly.Memory | null } = { current: null };

  const imports: WebAssembly.Imports = {
    env: {
      chacha_poly_decrypt: (
        out: number,
        outlen: number,
        ct: number,
        ctlen: number,
        key: number,
        iv: number,
        tag: number,
        _aad: number,
        _aadlen: number,
      ) => {
        const mem = memoryRef.current;
        if (!mem) return -1;
        return chachaPolyDecrypt(mem, out, outlen, ct, ctlen, key, iv, tag);
      },
    },
  };

  const result = await WebAssembly.instantiate(wasmBuffer, imports);
  const instance: WebAssembly.Instance =
    "instance" in result ? (result as { instance: WebAssembly.Instance }).instance : (result as WebAssembly.Instance);
  memoryRef.current = instance.exports.memory as WebAssembly.Memory;

  const vm_run = instance.exports.vm_run as (
    buf: number,
    buf_len: number,
    actions: number,
    actions_len: number,
    key: number,
    key_len: number,
  ) => number;

  vmInstance = { vm_run, memory: memoryRef.current };

  return { opcodesByAction: opcodesByAction! };
}

export function vmRun(
  buffer: Uint8Array,
  actions: (number | ActionName)[],
  key?: Uint8Array,
): number {
  if (!vmInstance) {
    throw new Error("loadVm() or loadVmFromChallenge() must be called before vmRun");
  }

  const mem = vmInstance.memory;
  const buf = new Uint8Array(mem.buffer);

  const opcodes: number[] = actions.map((a) => {
    if (typeof a === "number") return a;
    const op = opcodesByAction?.[a];
    if (op === undefined) throw new Error(`Unknown action: ${a}`);
    return op;
  });

  const pageSize = 65536;
  const heapBase = 64 * 1024; // safe region past typical static data
  const needed = heapBase + buffer.byteLength + opcodes.length + (key?.length ?? 0) + 64;
  const curSize = mem.buffer.byteLength;
  if (needed > curSize) {
    const needPages = Math.ceil(needed / pageSize);
    const curPages = Math.ceil(curSize / pageSize);
    if (needPages > curPages) mem.grow(needPages - curPages);
  }

  const heap = new Uint8Array(mem.buffer);
  const safeBufPtr = heapBase;
  const safeActionsPtr = safeBufPtr + buffer.length;
  const safeKeyPtr = safeActionsPtr + opcodes.length;

  heap.set(buffer, safeBufPtr);
  heap.set(opcodes, safeActionsPtr);
  if (key && key.length > 0) {
    heap.set(key, safeKeyPtr);
  }

  const rc = vmInstance.vm_run(
    safeBufPtr,
    buffer.length,
    safeActionsPtr,
    opcodes.length,
    key && key.length > 0 ? safeKeyPtr : 0,
    key?.length ?? 0,
  );

  if (rc === 0) {
    buffer.set(heap.subarray(safeBufPtr, safeBufPtr + buffer.length));
  }
  return rc;
}

export function getOpcode(action: ActionName): number {
  const op = opcodesByAction?.[action];
  if (op === undefined) throw new Error(`loadVm not called or unknown action: ${action}`);
  return op;
}

export function isVmLoaded(): boolean {
  return vmInstance !== null;
}

export interface ChallengeResponse {
  encryptedWasm: string;
  key: string;
  operations: { op: number; params: number[] }[];
  input: string;
  token: string;
}

const IV_LEN = 12;
const TAG_LEN = 16;

function unpackPacked(packed: Uint8Array): {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
} {
  if (packed.length < IV_LEN + TAG_LEN)
    throw new Error("Packed buffer too short");
  return {
    iv: packed.subarray(0, IV_LEN),
    ciphertext: packed.subarray(IV_LEN, packed.length - TAG_LEN),
    tag: packed.subarray(packed.length - TAG_LEN),
  };
}

export async function loadVmFromChallenge(
  challenge: ChallengeResponse,
): Promise<{ opcodesByAction: Record<string, number> }> {
  const packed = Uint8Array.from(
    atob(challenge.encryptedWasm),
    (c) => c.charCodeAt(0),
  );
  const key = Uint8Array.from(atob(challenge.key), (c) => c.charCodeAt(0));
  const { iv, ciphertext, tag } = unpackPacked(packed);

  const combined = new Uint8Array(ciphertext.length + TAG_LEN);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const chacha = chacha20poly1305(key, iv);
  const decrypted = chacha.decrypt(combined);
  const wasmBuffer = decrypted.buffer.slice(
    decrypted.byteOffset,
    decrypted.byteOffset + decrypted.byteLength,
  );

  opcodesByAction = {};

  const memoryRef: { current: WebAssembly.Memory | null } = { current: null };
  const imports: WebAssembly.Imports = {
    env: {
      chacha_poly_decrypt: (
        out: number,
        outlen: number,
        ct: number,
        ctlen: number,
        keyPtr: number,
        iv: number,
        tag: number,
        _aad: number,
        _aadlen: number,
      ) => {
        const mem = memoryRef.current;
        if (!mem) return -1;
        return chachaPolyDecrypt(mem, out, outlen, ct, ctlen, keyPtr, iv, tag);
      },
    },
  };

  const result = await WebAssembly.instantiate(wasmBuffer, imports);
  const instance: WebAssembly.Instance =
    "instance" in result ? (result as { instance: WebAssembly.Instance }).instance : (result as WebAssembly.Instance);
  memoryRef.current = instance.exports.memory as WebAssembly.Memory;
  const vm_run = instance.exports.vm_run as (
    buf: number,
    buf_len: number,
    actions: number,
    actions_len: number,
    key: number,
    key_len: number,
  ) => number;

  vmInstance = { vm_run, memory: memoryRef.current };

  return { opcodesByAction: opcodesByAction! };
}

export function vmRunWithOperations(
  buffer: Uint8Array,
  operations: { op: number; params: number[] }[],
): number {
  if (!vmInstance) {
    throw new Error("loadVmFromChallenge() or loadVm() must be called first");
  }

  for (const { op, params } of operations) {
    const key = params.length > 0 ? new Uint8Array(params) : undefined;
    const rc = vmRun(buffer, [op], key);
    if (rc !== 0) return rc;
  }
  return 0;
}
