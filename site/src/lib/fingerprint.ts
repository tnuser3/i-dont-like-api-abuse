import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import { set, get, sAdd, sMembers, expire } from "./redis";
import { crc32 } from "./checksum";
import { verifyChallengeToken } from "./jwt-challenge";

export interface FingerprintComponent {
  value?: unknown;
  error?: unknown;
  duration?: number;
}

export interface FingerprintComponents {
  [key: string]: FingerprintComponent;
}

export interface FingerprintPayload {
  visitorId: string;
  components: FingerprintComponents;
  confidence?: { score: number };
  version?: string;
}

export interface StoredDevice {
  deviceId: string;
  visitorIds: string[];
  components: FingerprintComponents;
  componentHashes: string[];
  firstSeen: number;
  lastSeen: number;
}

export interface FingerprintResponse {
  deviceId: string;
  linked: boolean;
  firstVisit: boolean;
}

const FP_PREFIX = "fp";
const DEV_PREFIX = `${FP_PREFIX}:dev`;
const COMP_PREFIX = `${FP_PREFIX}:ch`;
const DEV_ID_PREFIX = `${FP_PREFIX}:devid`;
const MIN_COMPONENT_OVERLAP = 3;
const DEVICE_TTL_SEC = 90 * 24 * 60 * 60;
const TIMESTAMP_MAX_AGE_MS = 5 * 60 * 1000;
const TIMESTAMP_MAX_FUTURE_MS = 60 * 1000;

function hashComponent(key: string, comp: FingerprintComponent): string | null {
  if ("error" in comp && comp.error) return null;
  const val = comp.value;
  if (val === undefined || val === null) return null;
  try {
    const str = `${key}:${JSON.stringify(val)}`;
    return crc32(new TextEncoder().encode(str)).toString(36);
  } catch {
    return null;
  }
}

function extractComponentHashes(components: FingerprintComponents): string[] {
  const hashes: string[] = [];
  for (const [key, comp] of Object.entries(components)) {
    const h = hashComponent(key, comp);
    if (h) hashes.push(`${key}:${h}`);
  }
  return hashes;
}

async function findMatchingDevice(componentHashes: string[]): Promise<string | null> {
  const deviceScores = new Map<string, number>();
  for (const ch of componentHashes) {
    for (const did of await sMembers(`${COMP_PREFIX}:${ch}`)) {
      deviceScores.set(did, (deviceScores.get(did) ?? 0) + 1);
    }
  }
  let bestDeviceId: string | null = null;
  let bestScore = MIN_COMPONENT_OVERLAP - 1;
  for (const [did, score] of deviceScores) {
    if (score > bestScore) {
      bestScore = score;
      bestDeviceId = did;
    }
  }
  return bestDeviceId;
}

export async function verifySignedFingerprint(body: {
  payload: FingerprintPayload;
  timestamp: number;
  signature: string;
  token: string;
}): Promise<FingerprintPayload> {
  const { payload, timestamp, signature, token } = body;

  if (!payload || typeof timestamp !== "number" || typeof signature !== "string" || typeof token !== "string") {
    throw new Error("Invalid signed fingerprint: missing fields");
  }

  const now = Date.now();
  if (now - timestamp > TIMESTAMP_MAX_AGE_MS) throw new Error("Invalid signed fingerprint: timestamp too old");
  if (timestamp > now + TIMESTAMP_MAX_FUTURE_MS) throw new Error("Invalid signed fingerprint: timestamp in future");

  let challengeId: string;
  try {
    challengeId = (await verifyChallengeToken(token)).challengeId;
  } catch {
    throw new Error("Invalid signed fingerprint: invalid or expired token");
  }

  const signingKeyB64 = await get<string>(`${FP_PREFIX}:sign:${challengeId}`);
  if (!signingKeyB64 || typeof signingKeyB64 !== "string") {
    throw new Error("Invalid signed fingerprint: signing key not found or expired");
  }

  const message = JSON.stringify(payload) + "|" + String(timestamp);
  const keyBuf = Buffer.from(signingKeyB64, "base64");
  const expectedSig = createHmac("sha256", keyBuf).update(message).digest("base64");
  const sigBuf = Buffer.from(signature, "base64");
  const expBuf = Buffer.from(expectedSig, "base64");
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    throw new Error("Invalid signed fingerprint: signature mismatch");
  }

  if (!payload.visitorId || typeof payload.visitorId !== "string" || !payload.components || typeof payload.components !== "object") {
    throw new Error("Invalid signed fingerprint: invalid payload");
  }

  return payload;
}

export async function storeFingerprint(payload: FingerprintPayload): Promise<FingerprintResponse> {
  const { visitorId, components } = payload;
  const now = Date.now();
  const componentHashes = extractComponentHashes(components);
  const existingKey = `${DEV_PREFIX}:${visitorId}`;
  const existing = await get<StoredDevice>(existingKey);

  if (existing) {
    await set(existingKey, { ...existing, components, componentHashes, lastSeen: now }, { exSeconds: DEVICE_TTL_SEC });
    return { deviceId: existing.deviceId, linked: false, firstVisit: false };
  }

  const matchedDeviceId = await findMatchingDevice(componentHashes);
  const deviceId = matchedDeviceId ?? randomUUID();
  const linked = !!matchedDeviceId;

  const record: StoredDevice = {
    deviceId,
    visitorIds: [visitorId],
    components,
    componentHashes,
    firstSeen: now,
    lastSeen: now,
  };

  await set(existingKey, record, { exSeconds: DEVICE_TTL_SEC });
  await sAdd(`${DEV_ID_PREFIX}:${deviceId}`, visitorId);
  await expire(`${DEV_ID_PREFIX}:${deviceId}`, DEVICE_TTL_SEC);

  for (const ch of componentHashes) {
    await sAdd(`${COMP_PREFIX}:${ch}`, deviceId);
    await expire(`${COMP_PREFIX}:${ch}`, DEVICE_TTL_SEC);
  }

  return { deviceId, linked, firstVisit: !linked };
}
