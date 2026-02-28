import { NextRequest, NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID, randomBytes } from "node:crypto";
import { chachaEncrypt, CHACHA_KEY_LENGTH } from "@/lib/chacha-poly";
import { run } from "@/lib/vm-encoder";
import { readU32LE } from "@/lib/encoding";
import { set } from "@/lib/redis";
import { signChallengeToken } from "@/lib/jwt-challenge";
import { logRouteRequest } from "@/lib/request-logger";

export interface ChallengeOperation {
  op: number;
  params: number[];
}

export interface ChallengeResponse {
  encryptedWasm: string;
  key: string;
  operations: ChallengeOperation[];
  input: string;
  token: string;
  signingKey: string;
}

function encodePacked(iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const packed = new Uint8Array(iv.length + ciphertext.length + tag.length);
  packed.set(iv, 0);
  packed.set(ciphertext, iv.length);
  packed.set(tag, iv.length + ciphertext.length);
  return packed;
}

function secureShuffle<T>(arr: T[]): T[] {
  const bytes = randomBytes(arr.length * 4);
  for (let i = arr.length - 1; i > 0; i--) {
    const r = (bytes[i * 4]! | (bytes[i * 4 + 1]! << 8) | (bytes[i * 4 + 2]! << 16) | (bytes[i * 4 + 3]! << 24)) >>> 0;
    const j = r % (i + 1);
    [arr[i], arr[j]] = [arr[j]!, arr[i]!];
  }
  return arr;
}

function secureRandomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const bytes = randomBytes(4);
  const r = (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;
  const threshold = (0xffffffff - (0xffffffff % maxExclusive)) >>> 0;
  if (r >= threshold) return secureRandomInt(maxExclusive);
  return r % maxExclusive;
}

export async function GET(request: NextRequest) {
  await logRouteRequest(request, "/api/challenge");
  try {
    const root = process.cwd();
    const wasmPath = join(root, "data", "crypto_utils.wasm");
    const bytecodesPath = join(root, "data", "bytecodes.json");

    const [wasmBuf, bytecodesBuf] = await Promise.all([
      readFile(wasmPath),
      readFile(bytecodesPath, "utf-8"),
    ]);

    const bytecodes = JSON.parse(bytecodesBuf) as {
      bytecodes: Record<string, string>;
      opcode_action: number[];
      vm: number[];
      vm_inv: number[];
    };

    const opcodeAction = bytecodes.opcode_action as number[];
    const opcodeBytes = Object.keys(bytecodes.bytecodes)
      .map((hex) => parseInt(hex, 16))
      .filter((op) => {
        if (op > 255) return false;
        const idx = opcodeAction[op];
        if (idx === 255 || idx === 18) return false;
        if (idx === 7 || idx === 8) return false;
        return true;
      });

    if (opcodeBytes.length === 0) {
      opcodeBytes.push(
        ...Object.keys(bytecodes.bytecodes).map((h) => parseInt(h, 16)),
      );
    }

    const key = randomBytes(CHACHA_KEY_LENGTH);
    const { ciphertext, authTag, iv } = await chachaEncrypt(
      new Uint8Array(key),
      new Uint8Array(wasmBuf)
    );

    const packed = encodePacked(iv, ciphertext, authTag);
    const encryptedWasm = Buffer.from(packed).toString("base64");

    const numOps = 8 + secureRandomInt(8);
    const numLayers = 2 + secureRandomInt(4);
    const layerSizes: number[] = [];
    let remaining = numOps;
    for (let i = 0; i < numLayers - 1; i++) {
      const minPerLayer = 1;
      const maxForLayer = Math.max(minPerLayer, remaining - (numLayers - i - 1) * minPerLayer);
      const range = Math.max(0, maxForLayer - minPerLayer + 1);
      const size = minPerLayer + (range > 0 ? secureRandomInt(range) : 0);
      layerSizes.push(Math.min(size, remaining));
      remaining -= layerSizes[i]!;
    }
    layerSizes.push(Math.max(1, remaining));

    const operations: ChallengeOperation[] = [];
    for (const layerSize of layerSizes) {
      const layerOps: ChallengeOperation[] = [];
      for (let i = 0; i < layerSize; i++) {
        const op = opcodeBytes[secureRandomInt(opcodeBytes.length)]!;
        const paramLen = secureRandomInt(8);
        const params = Array.from({ length: paramLen }, () => randomBytes(1)[0]!);
        layerOps.push({ op, params });
      }
      secureShuffle(layerOps);
      operations.push(...layerOps);
    }

    const inputBytes = randomBytes(8);
    const input = Buffer.from(inputBytes).toString("base64");

    const result = run(inputBytes, operations, {
      vm: bytecodes.vm,
      vm_inv: bytecodes.vm_inv,
      opcode_action: bytecodes.opcode_action,
    });
    const expected = result.length >= 4 ? readU32LE(result, 0) : 0;

    const challengeId = randomUUID();
    const signingKey = randomBytes(32);
    await set(`challenge:${challengeId}`, expected, { exSeconds: 300 });
    await set(`fp:sign:${challengeId}`, signingKey.toString("base64"), {
      exSeconds: 300,
    });

    const token = await signChallengeToken(challengeId);

    const response: ChallengeResponse = {
      encryptedWasm,
      key: key.toString("base64"),
      operations,
      input,
      token,
      signingKey: signingKey.toString("base64"),
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error("Challenge route error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  await logRouteRequest(request, "/api/challenge");
  try {
    const body = await request.json();
    return NextResponse.json({ message: "Created", data: body });
  } catch (error) {
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
