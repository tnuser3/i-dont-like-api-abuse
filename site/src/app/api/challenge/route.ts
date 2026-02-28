import { NextRequest, NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID, randomBytes } from "node:crypto";
import { chachaEncrypt, CHACHA_KEY_LENGTH } from "@/lib/chacha-poly";
import { run } from "@/lib/vm-encoder";
import { readU32LE } from "@/lib/encoding";
import { set, get } from "@/lib/redis";
import { signChallengeToken } from "@/lib/jwt-challenge";
import {
  createPublicKeySession,
  createEncryptionSession,
  encryptPayloadForResponse,
  decryptRequestBody,
} from "@/lib/key-session-server";
import { logRouteRequest } from "@/lib/request-logger";
import {
  storeFingerprint,
  verifySignedFingerprint,
  type FingerprintPayload,
  type FingerprintComponent,
} from "@/lib/fingerprint";
import type { ClientFingerprint, BehaviourEvent, SuspiciousFlags } from "@/lib/entropy";
import {
  crossReferenceEntropy,
  analyseBehaviour,
  computeFingerprintHash,
  deriveEntropy,
} from "@/lib/entropy";
import {
  processRequest,
  assessWebGLRenderer,
  assessFingerprintComponents,
  RISK_BLOCK_THRESHOLD,
} from "@/lib/request-risk-assessor";

export interface ChallengeOperation {
  op: number;
  params: number[];
}

export interface ChallengeCredentialsResponse {
  id: string;
  encryptedPublicKey: string;
}

export interface ChallengeResponse {
  encryptedWasm: string;
  key: string;
  operations: ChallengeOperation[];
  input: string;
  token: string;
  signingKey: string;
}

export interface EncryptedChallengeResponse {
  id: string;
  credential: string;
}

const SCORE_KEY_PREFIX = "entropy:score:";
const SCORE_TTL_SEC = 86_400;

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

function validateClientFingerprint(fp: unknown): fp is ClientFingerprint {
  if (!fp || typeof fp !== "object") return false;
  const f = fp as Record<string, unknown>;
  if (typeof f.timestamp !== "number") return false;
  if (typeof f.perfOrigin !== "number") return false;
  if (typeof f.userAgent !== "string") return false;
  if (typeof f.language !== "string") return false;
  if (!Array.isArray(f.languages)) return false;
  if (f.languages.some((x: unknown) => typeof x !== "string")) return false;
  if (typeof f.platform !== "string") return false;
  if (typeof f.hardwareConcurrency !== "number") return false;
  if (typeof f.screenWidth !== "number") return false;
  if (typeof f.screenHeight !== "number") return false;
  if (typeof f.availWidth !== "number") return false;
  if (typeof f.availHeight !== "number") return false;
  if (typeof f.colorDepth !== "number") return false;
  if (typeof f.pixelRatio !== "number") return false;
  if (typeof f.timezoneOffset !== "number") return false;
  if (typeof f.timezone !== "string") return false;
  if (typeof f.touchSupport !== "boolean") return false;
  if (typeof f.cookieEnabled !== "boolean") return false;
  return true;
}

function validateBehaviourEvent(e: unknown): e is BehaviourEvent {
  if (!e || typeof e !== "object") return false;
  const ev = e as Record<string, unknown>;
  if (typeof ev.type !== "string") return false;
  if (typeof ev.timestamp !== "number") return false;
  return true;
}

function validateEntropyPayload(body: unknown): {
  fingerprint: ClientFingerprint;
  entropyHex: string;
  timestamp: number;
  behaviour: { events: BehaviourEvent[]; flags: SuspiciousFlags };
  extraSeed?: string;
} | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (!validateClientFingerprint(b.fingerprint)) return null;
  if (typeof b.entropyHex !== "string" || !/^[0-9a-fA-F]+$/.test(b.entropyHex)) return null;
  if (typeof b.timestamp !== "number" || !Number.isFinite(b.timestamp)) return null;
  if (!b.behaviour || typeof b.behaviour !== "object") return null;
  const beh = b.behaviour as Record<string, unknown>;
  if (!Array.isArray(beh.events)) return null;
  if (!beh.events.every(validateBehaviourEvent)) return null;
  if (!beh.flags || typeof beh.flags !== "object") return null;
  const flags = beh.flags as Record<string, unknown>;
  if (typeof flags.rateLimitExceeded !== "boolean") return null;
  if (typeof flags.syntheticTimestamps !== "boolean") return null;
  if (typeof flags.automationPattern !== "boolean") return null;
  if (typeof flags.fingerprintAnomaly !== "boolean") return null;
  if (typeof flags.score !== "number") return null;
  const extraSeed = b.extraSeed;
  if (extraSeed !== undefined && typeof extraSeed !== "string") return null;
  return {
    fingerprint: b.fingerprint as ClientFingerprint,
    entropyHex: b.entropyHex as string,
    timestamp: b.timestamp as number,
    behaviour: b.behaviour as { events: BehaviourEvent[]; flags: SuspiciousFlags },
    ...(extraSeed !== undefined && { extraSeed: extraSeed as string }),
  };
}

function validateFingerprintComponent(c: unknown): c is FingerprintComponent {
  if (!c || typeof c !== "object") return false;
  const o = c as Record<string, unknown>;
  if (o.duration !== undefined && typeof o.duration !== "number") return false;
  return true;
}

function validateFingerprintPayload(body: unknown): {
  payload: Record<string, unknown>;
  timestamp: number;
  signature: string;
  token: string;
} | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (!b.payload || typeof b.payload !== "object") return null;
  const p = b.payload as Record<string, unknown>;
  if (typeof p.visitorId !== "string" || p.visitorId.length === 0) return null;
  if (!p.components || typeof p.components !== "object" || Array.isArray(p.components)) return null;
  const comps = p.components as Record<string, unknown>;
  for (const v of Object.values(comps)) {
    if (!validateFingerprintComponent(v)) return null;
  }
  if (typeof b.timestamp !== "number" || !Number.isFinite(b.timestamp)) return null;
  if (typeof b.signature !== "string" || b.signature.length === 0) return null;
  if (typeof b.token !== "string" || b.token.length === 0) return null;
  return {
    payload: p,
    timestamp: b.timestamp as number,
    signature: b.signature as string,
    token: b.token as string,
  };
}

async function createFullChallenge(): Promise<{
  challengeId: string;
  response: EncryptedChallengeResponse;
  expected: number;
}> {
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
    opcodeBytes.push(...Object.keys(bytecodes.bytecodes).map((h) => parseInt(h, 16)));
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
  await set(`fp:sign:${challengeId}`, signingKey.toString("base64"), { exSeconds: 300 });

  const vmToken = await signChallengeToken(challengeId);

  const response: ChallengeResponse = {
    encryptedWasm,
    key: key.toString("base64"),
    operations,
    input,
    token: vmToken,
    signingKey: signingKey.toString("base64"),
  };

  const { id: encId, sessionKey } = await createEncryptionSession();
  const credential = encryptPayloadForResponse(sessionKey, response);

  return {
    challengeId,
    response: { id: encId, credential },
    expected,
  };
}

export async function GET(request: NextRequest) {
  const risk = await processRequest(request);
  if (risk.blocked) return risk.response;
  await logRouteRequest(request, "/api/challenge");
  try {
    const { id, encryptedPublicKey } = await createPublicKeySession();

    return NextResponse.json({ id, encryptedPublicKey });
  } catch (error) {
    console.error("Challenge GET error:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const risk = await processRequest(request);
  if (risk.blocked) return risk.response;
  await logRouteRequest(request, "/api/challenge");
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== "object") {
      return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
    }
    const envelope = raw as { id?: string; body?: string };
    if (typeof envelope.id !== "string" || typeof envelope.body !== "string") {
      return NextResponse.json({ error: "Invalid payload: id and body required" }, { status: 400 });
    }

    let body: Record<string, unknown>;
    try {
      body = (await decryptRequestBody(envelope.id, envelope.body)) as Record<string, unknown>;
    } catch (err) {
      return NextResponse.json(
        { error: err instanceof Error ? err.message : "Decryption failed" },
        { status: 400 }
      );
    }

    const b = body;
    const entropyData = validateEntropyPayload(b.entropy);
    const fingerprintData = validateFingerprintPayload(b.fingerprint);

    if (!entropyData) {
      return NextResponse.json(
        { error: "Invalid entropy: fingerprint, entropyHex, timestamp, behaviour with events and flags required" },
        { status: 400 }
      );
    }

    if (!fingerprintData) {
      return NextResponse.json(
        { error: "Invalid fingerprint: payload.visitorId, payload.components, timestamp, signature, token required" },
        { status: 400 }
      );
    }

    const fp = entropyData.fingerprint;
    const webglStr = [fp.webglRenderer, fp.webglVendor].filter(Boolean).join(" ");
    const webglAssessment = assessWebGLRenderer(webglStr || undefined);
    const comps = (fingerprintData.payload as { components?: Record<string, { value?: unknown; error?: unknown; duration?: number }> }).components ?? {};
    const fpComponentsAssessment = assessFingerprintComponents(comps, fp.webglVendor);
    const headerScore = risk.blocked === false ? risk.assessment.score : 0;
    const totalRisk = headerScore + webglAssessment.score + fpComponentsAssessment.score;
    if (totalRisk >= RISK_BLOCK_THRESHOLD) {
      const reasons = [
        ...(risk.blocked === false ? risk.assessment.reasons : []),
        ...webglAssessment.reasons,
        ...fpComponentsAssessment.reasons,
      ];
      return NextResponse.json(
        { error: "Blocked", reasons },
        { status: 403 }
      );
    }

    let fingerprintPayload;
    try {
      fingerprintPayload = await verifySignedFingerprint(fingerprintData);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Fingerprint verification failed";
      await logRouteRequest(request, "/api/challenge", String(fingerprintData.payload.visitorId));
      return NextResponse.json({ error: msg }, { status: 401 });
    }

    await logRouteRequest(request, "/api/challenge", fingerprintPayload.visitorId);

    await storeFingerprint(fingerprintPayload);

    const { score: crossScore, reasons } = crossReferenceEntropy(
      entropyData.fingerprint,
      request.headers,
      entropyData.timestamp,
      entropyData.entropyHex,
      entropyData.extraSeed
    );

    const { score: behaviourScore, flags: behaviourFlags } = analyseBehaviour(entropyData.behaviour.events);

    const totalScore = Math.min(1, crossScore + behaviourScore);

    if (totalScore >= 0.7) {
      return NextResponse.json(
        { error: "Entropy validation failed", score: totalScore, reasons },
        { status: 403 }
      );
    }

    try {
      const fpHash = computeFingerprintHash(entropyData.fingerprint);
      const storageKey = `${SCORE_KEY_PREFIX}${fpHash}`;
      const existing = await get<{ score: number; count: number }>(storageKey);
      const count = (existing?.count ?? 0) + 1;
      const cumScore = (existing?.score ?? 0) + totalScore;
      await set(storageKey, { score: cumScore, count }, { exSeconds: SCORE_TTL_SEC });
    } catch {}

    const { response } = await createFullChallenge();

    return NextResponse.json(response);
  } catch (error) {
    console.error("Challenge POST error:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
