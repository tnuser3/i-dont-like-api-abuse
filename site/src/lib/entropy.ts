/**
 * Client entropy utility: collects identifying system values, timestamps,
 * and tracks suspicious behaviour for abuse detection.
 */

import { crc32 } from "./checksum";
import { toHex } from "./encoding";

/** Identifying system values collected from the client environment */
export interface ClientFingerprint {
  /** High-resolution timestamp at collection */
  timestamp: number;
  /** Performance timing origin (page load reference) */
  perfOrigin: number;
  /** User agent string */
  userAgent: string;
  /** Primary language */
  language: string;
  /** All preferred languages */
  languages: string[];
  /** Platform (e.g. Win32, MacIntel) */
  platform: string;
  /** Number of logical CPU cores */
  hardwareConcurrency: number;
  /** Device memory in GB (if available) */
  deviceMemory?: number;
  /** Screen dimensions */
  screenWidth: number;
  screenHeight: number;
  /** Available screen space (minus taskbar etc.) */
  availWidth: number;
  availHeight: number;
  /** Color depth in bits */
  colorDepth: number;
  /** Pixel ratio */
  pixelRatio: number;
  /** Timezone offset in minutes */
  timezoneOffset: number;
  /** Timezone name (e.g. America/New_York) */
  timezone: string;
  /** Touch support */
  touchSupport: boolean;
  /** Cookie enabled */
  cookieEnabled: boolean;
  /** Canvas fingerprint hash (simple) */
  canvasHash?: number;
  /** WebGL vendor/renderer hash */
  webglHash?: number;
}

/** Event recorded for behaviour tracking */
export interface BehaviourEvent {
  type: string;
  timestamp: number;
  payload?: Record<string, unknown>;
}

/** Suspicious behaviour flags */
export interface SuspiciousFlags {
  /** Too many events in a short window */
  rateLimitExceeded: boolean;
  /** Timestamps look synthetic (too regular) */
  syntheticTimestamps: boolean;
  /** Request pattern matches automation (e.g. fixed intervals) */
  automationPattern: boolean;
  /** Fingerprint mismatch or inconsistency */
  fingerprintAnomaly: boolean;
  /** Score 0–1, higher = more suspicious */
  score: number;
}

const BEHAVIOUR_WINDOW_MS = 60_000;
const RATE_LIMIT_THRESHOLD = 30;
const MIN_INTERVAL_MS = 50;
const AUTOMATION_TOLERANCE_MS = 5;

/** Collect identifying system values from the client (browser) */
export function collectFingerprint(): ClientFingerprint {
  const nav = typeof navigator !== "undefined" ? navigator : ({} as Navigator);
  const scr = typeof screen !== "undefined" ? screen : ({} as Screen);
  const perf = typeof performance !== "undefined" ? performance : ({} as Performance);
  const now = typeof Date !== "undefined" ? Date.now() : 0;
  const perfNow = perf.now ? perf.now() : 0;

  const fingerprint: ClientFingerprint = {
    timestamp: now,
    perfOrigin: perfNow,
    userAgent: nav.userAgent ?? "",
    language: nav.language ?? "",
    languages: Array.isArray(nav.languages) ? [...nav.languages] : [],
    platform: nav.platform ?? "",
    hardwareConcurrency: nav.hardwareConcurrency ?? 0,
    screenWidth: scr.width ?? 0,
    screenHeight: scr.height ?? 0,
    availWidth: scr.availWidth ?? 0,
    availHeight: scr.availHeight ?? 0,
    colorDepth: scr.colorDepth ?? 0,
    pixelRatio: typeof window !== "undefined" && window.devicePixelRatio ? window.devicePixelRatio : 1,
    timezoneOffset: typeof Intl !== "undefined"
      ? -new Date().getTimezoneOffset()
      : 0,
    timezone: typeof Intl !== "undefined"
      ? Intl.DateTimeFormat().resolvedOptions().timeZone
      : "",
    touchSupport:
      "ontouchstart" in (typeof window !== "undefined" ? window : {}),
    cookieEnabled: nav.cookieEnabled ?? false,
  };

  const navWithMemory = nav as Navigator & { deviceMemory?: number };
  if (typeof navWithMemory.deviceMemory === "number") {
    fingerprint.deviceMemory = navWithMemory.deviceMemory;
  }

  try {
    fingerprint.canvasHash = getCanvasHash();
  } catch {
    fingerprint.canvasHash = 0;
  }

  try {
    fingerprint.webglHash = getWebGLHash();
  } catch {
    fingerprint.webglHash = 0;
  }

  return fingerprint;
}

/** Simple canvas fingerprint for entropy (does not render to DOM) */
function getCanvasHash(): number {
  if (typeof document === "undefined" || !document.createElement) return 0;
  const canvas = document.createElement("canvas");
  canvas.width = 200;
  canvas.height = 50;
  const ctx = canvas.getContext("2d");
  if (!ctx) return 0;
  ctx.textBaseline = "top";
  ctx.font = "14px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillRect(0, 0, 100, 50);
  ctx.fillStyle = "#069";
  ctx.fillText("entropy", 2, 15);
  const data = canvas.toDataURL();
  const bytes = new TextEncoder().encode(data);
  return crc32(new Uint8Array(bytes));
}

/** WebGL vendor/renderer hash */
function getWebGLHash(): number {
  if (typeof document === "undefined" || !document.createElement) return 0;
  const canvas = document.createElement("canvas");
  const gl = (canvas.getContext("webgl") ?? canvas.getContext("experimental-webgl")) as WebGLRenderingContext | null;
  if (!gl) return 0;
  const ext = gl.getExtension("WEBGL_debug_renderer_info");
  if (!ext) return 0;
  const UNMASKED_VENDOR_WEBGL = 0x9245;
  const UNMASKED_RENDERER_WEBGL = 0x9246;
  const vendor = gl.getParameter(UNMASKED_VENDOR_WEBGL) ?? "";
  const renderer = gl.getParameter(UNMASKED_RENDERER_WEBGL) ?? "";
  const str = `${vendor}|${renderer}`;
  const bytes = new TextEncoder().encode(str);
  return crc32(new Uint8Array(bytes));
}

/** Serialize fingerprint to bytes for hashing */
function fingerprintToBytes(fp: ClientFingerprint): Uint8Array {
  const parts: string[] = [
    String(fp.timestamp),
    String(fp.perfOrigin),
    fp.userAgent,
    fp.language,
    fp.languages.join(","),
    fp.platform,
    String(fp.hardwareConcurrency),
    String(fp.deviceMemory ?? 0),
    String(fp.screenWidth),
    String(fp.screenHeight),
    String(fp.availWidth),
    String(fp.availHeight),
    String(fp.colorDepth),
    String(fp.pixelRatio),
    String(fp.timezoneOffset),
    fp.timezone,
    fp.touchSupport ? "1" : "0",
    fp.cookieEnabled ? "1" : "0",
    String(fp.canvasHash ?? 0),
    String(fp.webglHash ?? 0),
  ];
  const str = parts.join("|");
  return new TextEncoder().encode(str);
}

/** Derive entropy bytes from fingerprint + optional extra seed */
export function deriveEntropy(
  fingerprint: ClientFingerprint,
  extraSeed?: string | Uint8Array,
  outputLength = 32
): Uint8Array {
  const base = fingerprintToBytes(fingerprint);
  let combined = new Uint8Array(base.length);
  combined.set(base);

  if (extraSeed !== undefined) {
    const extra =
      typeof extraSeed === "string"
        ? new TextEncoder().encode(extraSeed)
        : extraSeed;
    const newCombined = new Uint8Array(combined.length + extra.length);
    newCombined.set(combined);
    newCombined.set(extra, combined.length);
    combined = newCombined;
  }

  const out = new Uint8Array(outputLength);
  let hash = crc32(combined);

  for (let i = 0; i < outputLength; i += 4) {
    hash = (hash * 1664525 + 1013904223) >>> 0;
    out[i] = (hash >>> 24) & 0xff;
    if (i + 1 < outputLength) out[i + 1] = (hash >>> 16) & 0xff;
    if (i + 2 < outputLength) out[i + 2] = (hash >>> 8) & 0xff;
    if (i + 3 < outputLength) out[i + 3] = hash & 0xff;
  }

  return out;
}

/** Behaviour tracker for detecting suspicious patterns */
export class BehaviourTracker {
  private events: BehaviourEvent[] = [];
  private lastFingerprint: ClientFingerprint | null = null;

  /** Record an event (e.g. API call, challenge request) */
  record(type: string, payload?: Record<string, unknown>): void {
    this.events.push({
      type,
      timestamp: Date.now(),
      payload,
    });
    this.prune();
  }

  /** Update stored fingerprint for anomaly detection */
  setFingerprint(fp: ClientFingerprint): void {
    this.lastFingerprint = fp;
  }

  private prune(): void {
    const cutoff = Date.now() - BEHAVIOUR_WINDOW_MS;
    this.events = this.events.filter((e) => e.timestamp >= cutoff);
  }

  /** Analyse behaviour and return suspicious flags */
  analyse(): SuspiciousFlags {
    this.prune();
    const flags: SuspiciousFlags = {
      rateLimitExceeded: false,
      syntheticTimestamps: false,
      automationPattern: false,
      fingerprintAnomaly: false,
      score: 0,
    };

    if (this.events.length === 0) return flags;

    const count = this.events.length;
    flags.rateLimitExceeded = count >= RATE_LIMIT_THRESHOLD;
    if (flags.rateLimitExceeded) flags.score += 0.4;

    const timestamps = this.events.map((e) => e.timestamp).sort((a, b) => a - b);
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i]! - timestamps[i - 1]!);
    }

    const tooFast = intervals.some((d) => d < MIN_INTERVAL_MS);
    if (tooFast) {
      flags.syntheticTimestamps = true;
      flags.score += 0.3;
    }

    if (intervals.length >= 3) {
      const mean =
        intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance =
        intervals.reduce((s, d) => s + (d - mean) ** 2, 0) / intervals.length;
      const stdDev = Math.sqrt(variance);
      if (mean > 0 && stdDev < AUTOMATION_TOLERANCE_MS) {
        flags.automationPattern = true;
        flags.score += 0.3;
      }
    }

    flags.score = Math.min(1, flags.score);
    return flags;
  }

  /** Get events in the current window (for server submission) */
  getEvents(): BehaviourEvent[] {
    this.prune();
    return [...this.events];
  }

  /** Clear tracked events */
  clear(): void {
    this.events = [];
  }
}

/** Singleton tracker for app-wide use */
let defaultTracker: BehaviourTracker | null = null;

/** Get the default behaviour tracker */
export function getBehaviourTracker(): BehaviourTracker {
  if (!defaultTracker) defaultTracker = new BehaviourTracker();
  return defaultTracker;
}

/** Payload sent to server for entropy validation */
export interface EntropySubmitPayload {
  fingerprint: ClientFingerprint;
  entropyHex: string;
  timestamp: number;
  behaviour: { events: BehaviourEvent[]; flags: SuspiciousFlags };
  extraSeed?: string;
}

/** Response from entropy API */
export interface EntropySubmitResponse {
  ok: boolean;
  flags: SuspiciousFlags;
  score: number;
  message?: string;
  /** Mismatch reasons when fingerprint anomaly detected */
  reasons?: string[];
}

/** Submit entropy to server for validation and scoring. Call from client. */
export async function submitEntropy(
  baseUrl = "",
  extraSeed?: string
): Promise<EntropySubmitResponse> {
  const payload = createEntropyPayload(extraSeed);
  const body: EntropySubmitPayload = {
    fingerprint: payload.fingerprint,
    entropyHex: toHex(payload.entropy),
    timestamp: payload.timestamp,
    behaviour: payload.behaviour,
    ...(extraSeed !== undefined && { extraSeed }),
  };

  const res = await fetch(`${baseUrl}/api/entropy`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((err as { error?: string }).error ?? "Entropy submit failed");
  }

  return res.json() as Promise<EntropySubmitResponse>;
}

/** Create full entropy payload: fingerprint + derived bytes + behaviour snapshot */
export function createEntropyPayload(extraSeed?: string): {
  fingerprint: ClientFingerprint;
  entropy: Uint8Array;
  timestamp: number;
  behaviour: { events: BehaviourEvent[]; flags: SuspiciousFlags };
} {
  const fp = collectFingerprint();
  const tracker = getBehaviourTracker();
  tracker.setFingerprint(fp);
  tracker.record("entropy_collect");

  const entropy = deriveEntropy(fp, extraSeed);
  const flags = tracker.analyse();
  const events = tracker.getEvents();

  return {
    fingerprint: fp,
    entropy,
    timestamp: fp.timestamp,
    behaviour: { events, flags },
  };
}
