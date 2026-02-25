import { NextRequest, NextResponse } from "next/server";
import type { ClientFingerprint, BehaviourEvent, SuspiciousFlags } from "@/lib/entropy";
import { deriveEntropy } from "@/lib/entropy";
import { fromHex } from "@/lib/encoding";
import { set, get } from "@/lib/redis";

/** Max client-server timestamp drift (ms) before flagging */
const MAX_TIMESTAMP_DRIFT_MS = 120_000; // 2 minutes
/** Score per mismatch (max 1.0 total from cross-reference) */
const USER_AGENT_MISMATCH = 0.35;
const LANGUAGE_MISMATCH = 0.25;
const TIMESTAMP_DRIFT = 0.3;
const ENTROPY_MISMATCH = 0.4;
/** Store score by fingerprint hash, 24h expiry */
const SCORE_KEY_PREFIX = "entropy:score:";
const SCORE_TTL_SEC = 86_400;

function computeFingerprintHash(fp: ClientFingerprint): string {
  const str = [
    fp.userAgent,
    fp.language,
    fp.platform,
    String(fp.hardwareConcurrency),
    String(fp.screenWidth),
    String(fp.screenHeight),
    fp.timezone,
  ].join("|");
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) >>> 0;
  }
  return h.toString(36);
}

function crossReference(
  fingerprint: ClientFingerprint,
  headers: Headers,
  clientTimestamp: number,
  entropyHex: string,
  extraSeed?: string
): { score: number; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];
  const uaHeader = headers.get("user-agent") ?? "";
  const acceptLang = headers.get("accept-language") ?? "";

  // User-Agent: client claims vs what server sees
  if (fingerprint.userAgent && uaHeader) {
    const normClient = fingerprint.userAgent.trim().toLowerCase();
    const normHeader = uaHeader.trim().toLowerCase();
    if (normClient !== normHeader) {
      score += USER_AGENT_MISMATCH;
      reasons.push("user_agent_mismatch");
    }
  } else if (!uaHeader && fingerprint.userAgent) {
    score += USER_AGENT_MISMATCH;
    reasons.push("user_agent_missing_header");
  }

  // Accept-Language vs client language/languages
  if (fingerprint.language && acceptLang) {
    const clientLang = fingerprint.language.toLowerCase().split("-")[0];
    const headerLangs = acceptLang
      .toLowerCase()
      .split(",")
      .map((s) => s.split(";")[0]!.trim().split("-")[0]);
    if (clientLang && !headerLangs.some((h) => h === clientLang)) {
      score += LANGUAGE_MISMATCH;
      reasons.push("language_mismatch");
    }
  }

  // Timestamp drift: client time vs server time
  const serverNow = Date.now();
  const drift = Math.abs(serverNow - clientTimestamp);
  if (drift > MAX_TIMESTAMP_DRIFT_MS) {
    score += TIMESTAMP_DRIFT;
    reasons.push("timestamp_drift");
  }

  // Entropy: recompute and compare (fingerprint + extraSeed)
  try {
    const expected = deriveEntropy(fingerprint, extraSeed);
    const received = fromHex(entropyHex);
    if (expected.length !== received.length) {
      score += ENTROPY_MISMATCH;
      reasons.push("entropy_length_mismatch");
    } else {
      let match = true;
      for (let i = 0; i < expected.length; i++) {
        if (expected[i] !== received[i]) {
          match = false;
          break;
        }
      }
      if (!match) {
        score += ENTROPY_MISMATCH;
        reasons.push("entropy_mismatch");
      }
    }
  } catch {
    score += ENTROPY_MISMATCH;
    reasons.push("entropy_invalid");
  }

  return { score, reasons };
}

function analyseBehaviour(events: BehaviourEvent[]): { score: number; flags: Partial<SuspiciousFlags> } {
  const RATE_LIMIT = 30;
  const MIN_INTERVAL_MS = 50;
  const AUTOMATION_TOLERANCE_MS = 5;

  let score = 0;
  const flags: Partial<SuspiciousFlags> = {};

  if (events.length === 0) return { score: 0, flags };

  flags.rateLimitExceeded = events.length >= RATE_LIMIT;
  if (flags.rateLimitExceeded) score += 0.4;

  const timestamps = events.map((e) => e.timestamp).sort((a, b) => a - b);
  const intervals: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i]! - timestamps[i - 1]!);
  }

  const tooFast = intervals.some((d) => d < MIN_INTERVAL_MS);
  flags.syntheticTimestamps = tooFast;
  if (tooFast) score += 0.3;

  if (intervals.length >= 3) {
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((s, d) => s + (d - mean) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    flags.automationPattern = mean > 0 && stdDev < AUTOMATION_TOLERANCE_MS;
    if (flags.automationPattern) score += 0.3;
  }

  return { score, flags };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const {
      fingerprint,
      entropyHex,
      timestamp,
      behaviour,
      extraSeed,
    } = body as {
      fingerprint: ClientFingerprint;
      entropyHex: string;
      timestamp: number;
      behaviour: { events: BehaviourEvent[]; flags: SuspiciousFlags };
      extraSeed?: string;
    };

    if (!fingerprint || typeof entropyHex !== "string" || !behaviour?.events) {
      return NextResponse.json(
        { ok: false, flags: {}, score: 1, message: "Invalid payload" },
        { status: 400 }
      );
    }

    // Cross-reference server headers vs client claims
    const { score: crossScore, reasons } = crossReference(
      fingerprint,
      request.headers,
      timestamp,
      entropyHex,
      extraSeed
    );

    // Re-analyse behaviour on server
    const { score: behaviourScore, flags: behaviourFlags } = analyseBehaviour(
      behaviour.events
    );

    const fingerprintAnomaly = crossScore > 0;
    const totalScore = Math.min(1, crossScore + behaviourScore);

    const flags: SuspiciousFlags = {
      rateLimitExceeded: behaviourFlags.rateLimitExceeded ?? false,
      syntheticTimestamps: behaviourFlags.syntheticTimestamps ?? false,
      automationPattern: behaviourFlags.automationPattern ?? false,
      fingerprintAnomaly,
      score: totalScore,
    };

    // Persist score by fingerprint for rate/abuse tracking (optional, Redis may be unavailable)
    try {
      const fpHash = computeFingerprintHash(fingerprint);
      const storageKey = `${SCORE_KEY_PREFIX}${fpHash}`;
      const existing = await get<{ score: number; count: number }>(storageKey);
      const count = (existing?.count ?? 0) + 1;
      const cumScore = (existing?.score ?? 0) + totalScore;
      await set(storageKey, { score: cumScore, count }, { exSeconds: SCORE_TTL_SEC });
    } catch {
      // Redis unavailable – continue without persistence
    }

    return NextResponse.json({
      ok: totalScore < 0.7,
      flags,
      score: totalScore,
      reasons: reasons.length > 0 ? reasons : undefined,
    });
  } catch (error) {
    console.error("Entropy route error:", error);
    return NextResponse.json(
      { ok: false, flags: {}, score: 1, message: "Internal error" },
      { status: 500 }
    );
  }
}
