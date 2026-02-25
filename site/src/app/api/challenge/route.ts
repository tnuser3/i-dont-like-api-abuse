import { NextRequest, NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { chachaEncrypt, CHACHA_KEY_LENGTH } from "@/lib/chacha-poly";
import { randomBytes } from "node:crypto";
import { run } from "@/lib/vm-encoder";
import { readU32LE } from "@/lib/encoding";
import { set } from "@/lib/redis";
import { signChallengeToken } from "@/lib/jwt-challenge";

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
}

function encodePacked(iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const packed = new Uint8Array(iv.length + ciphertext.length + tag.length);
  packed.set(iv, 0);
  packed.set(ciphertext, iv.length);
  packed.set(tag, iv.length + ciphertext.length);
  return packed;
}

function shuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j]!, arr[i]!];
  }
  return arr;
}

export async function GET(request: NextRequest) {
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

    const numOps = 8 + Math.floor(Math.random() * 8);
    const numLayers = 2 + Math.floor(Math.random() * 4);
    const layerSizes: number[] = [];
    let remaining = numOps;
    for (let i = 0; i < numLayers - 1; i++) {
      const minPerLayer = 1;
      const maxForLayer = Math.max(minPerLayer, remaining - (numLayers - i - 1) * minPerLayer);
      const size = minPerLayer + Math.floor(Math.random() * Math.max(0, maxForLayer - minPerLayer + 1));
      layerSizes.push(Math.min(size, remaining));
      remaining -= layerSizes[i]!;
    }
    layerSizes.push(Math.max(1, remaining));

    const operations: ChallengeOperation[] = [];
    for (const layerSize of layerSizes) {
      const layerOps: ChallengeOperation[] = [];
      for (let i = 0; i < layerSize; i++) {
        const op = opcodeBytes[Math.floor(Math.random() * opcodeBytes.length)]!;
        const paramLen = Math.floor(Math.random() * 8);
        const params = Array.from({ length: paramLen }, () =>
          Math.floor(Math.random() * 256)
        );
        layerOps.push({ op, params });
      }
      shuffle(layerOps);
      operations.push(...layerOps);
    }

    const inputBytes = new Uint8Array(4);
    inputBytes[0] = Math.floor(Math.random() * 256);
    inputBytes[1] = Math.floor(Math.random() * 256);
    inputBytes[2] = Math.floor(Math.random() * 256);
    inputBytes[3] = Math.floor(Math.random() * 256);
    const input = Buffer.from(inputBytes).toString("base64");

    const result = run(inputBytes, operations, {
      vm: bytecodes.vm,
      vm_inv: bytecodes.vm_inv,
      opcode_action: bytecodes.opcode_action,
    });
    const expected = result.length >= 4 ? readU32LE(result, 0) : 0;

    const challengeId = randomUUID();
    await set(`challenge:${challengeId}`, expected, { exSeconds: 300 });

    const token = await signChallengeToken(challengeId);

    const response: ChallengeResponse = {
      encryptedWasm,
      key: key.toString("base64"),
      operations,
      input,
      token,
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
