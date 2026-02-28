import { crc32 } from "./checksum";
import { toHex, fromHex } from "./encoding";

export { toHex };

export interface ClientFingerprint {
  timestamp: number;
  perfOrigin: number;
  userAgent: string;
  language: string;
  languages: string[];
  platform: string;
  hardwareConcurrency: number;
  deviceMemory?: number;
  screenWidth: number;
  screenHeight: number;
  availWidth: number;
  availHeight: number;
  colorDepth: number;
  pixelRatio: number;
  timezoneOffset: number;
  timezone: string;
  touchSupport: boolean;
  cookieEnabled: boolean;
  canvasHash?: number;
  webglHash?: number;
  webglVendor?: string;
  webglRenderer?: string;
  webgl2Hash?: number;
  audioHash?: number;
  fontsHash?: number;
  pluginsHash?: number;
  webdriver?: boolean;
  innerWidth?: number;
  innerHeight?: number;
  outerWidth?: number;
  outerHeight?: number;
}

export interface BehaviourEvent {
  type: string;
  timestamp: number;
  payload?: Record<string, unknown>;
}

export interface SuspiciousFlags {
  rateLimitExceeded: boolean;
  syntheticTimestamps: boolean;
  automationPattern: boolean;
  fingerprintAnomaly: boolean;
  score: number;
}

const BEHAVIOUR_WINDOW_MS = 60_000;
const RATE_LIMIT_THRESHOLD = 30;
const MIN_INTERVAL_MS = 50;
const AUTOMATION_TOLERANCE_MS = 5;

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
    const webgl = getWebGLInfo();
    fingerprint.webglHash = webgl.hash;
    fingerprint.webglVendor = webgl.vendor;
    fingerprint.webglRenderer = webgl.renderer;
  } catch {
    fingerprint.webglHash = 0;
  }

  try {
    fingerprint.webgl2Hash = getWebGL2Hash();
  } catch {
    fingerprint.webgl2Hash = 0;
  }

  try {
    fingerprint.audioHash = getAudioHash();
  } catch {
    fingerprint.audioHash = 0;
  }

  try {
    fingerprint.fontsHash = getFontsHash();
  } catch {
    fingerprint.fontsHash = 0;
  }

  try {
    fingerprint.pluginsHash = getPluginsHash();
  } catch {
    fingerprint.pluginsHash = 0;
  }

  if (typeof navigator !== "undefined") {
    fingerprint.webdriver = !!(navigator as Navigator & { webdriver?: boolean }).webdriver;
  }

  if (typeof window !== "undefined") {
    fingerprint.innerWidth = window.innerWidth;
    fingerprint.innerHeight = window.innerHeight;
    fingerprint.outerWidth = window.outerWidth;
    fingerprint.outerHeight = window.outerHeight;
  }

  return fingerprint;
}

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

function getWebGLInfo(): { hash: number; vendor: string; renderer: string } {
  if (typeof document === "undefined" || !document.createElement) {
    return { hash: 0, vendor: "", renderer: "" };
  }
  const canvas = document.createElement("canvas");
  const gl = (canvas.getContext("webgl") ?? canvas.getContext("experimental-webgl")) as WebGLRenderingContext | null;
  if (!gl) return { hash: 0, vendor: "", renderer: "" };
  const ext = gl.getExtension("WEBGL_debug_renderer_info");
  if (!ext) return { hash: 0, vendor: "", renderer: "" };
  const UNMASKED_VENDOR_WEBGL = 0x9245;
  const UNMASKED_RENDERER_WEBGL = 0x9246;
  const vendor = String(gl.getParameter(UNMASKED_VENDOR_WEBGL) ?? "");
  const renderer = String(gl.getParameter(UNMASKED_RENDERER_WEBGL) ?? "");
  const str = `${vendor}|${renderer}`;
  const bytes = new TextEncoder().encode(str);
  return { hash: crc32(new Uint8Array(bytes)), vendor, renderer };
}

function getWebGL2Hash(): number {
  if (typeof document === "undefined" || !document.createElement) return 0;
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl2") as WebGL2RenderingContext | null;
  if (!gl) return 0;
  const params: string[] = [
    String(gl.getParameter(gl.MAX_TEXTURE_SIZE) ?? 0),
    String(gl.getParameter(gl.MAX_VIEWPORT_DIMS) ?? ""),
    String(gl.getParameter(gl.MAX_VERTEX_ATTRIBS) ?? 0),
    String(gl.getParameter(gl.RENDERER) ?? ""),
    String(gl.getParameter(gl.VENDOR) ?? ""),
  ];
  const str = params.join("|");
  return crc32(new TextEncoder().encode(str));
}

function getAudioHash(): number {
  if (typeof window === "undefined") return 0;
  const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctx) return 0;
  const ctx = new Ctx();
  const str = `${ctx.sampleRate}|${(ctx as AudioContext & { baseLatency?: number }).baseLatency ?? 0}|${ctx.state}`;
  ctx.close();
  return crc32(new TextEncoder().encode(str));
}

function getFontsHash(): number {
  if (typeof document === "undefined" || !document.body) return 0;
  const testFonts = ["Arial", "Helvetica", "Times New Roman", "Courier New", "Verdana", "Georgia", "Palatino", "Garamond", "Comic Sans MS", "Trebuchet MS", "Impact"];
  const baseFont = "monospace";
  const testStr = "mmMwWLliI0O&1";
  const widths: number[] = [];
  const span = document.createElement("span");
  span.style.position = "absolute";
  span.style.left = "-9999px";
  span.style.fontSize = "72px";
  span.textContent = testStr;
  document.body.appendChild(span);
  for (const font of testFonts) {
    span.style.fontFamily = `"${font}", ${baseFont}`;
    widths.push(span.offsetWidth);
  }
  document.body.removeChild(span);
  const str = widths.join("|");
  return crc32(new TextEncoder().encode(str));
}

function getPluginsHash(): number {
  if (typeof navigator === "undefined") return 0;
  const nav = navigator as Navigator & { plugins?: { length: number; [i: number]: { name: string } }; mimeTypes?: { length: number } };
  let str = "";
  if (nav.plugins) {
    for (let i = 0; i < Math.min(nav.plugins.length, 20); i++) {
      str += nav.plugins[i]?.name ?? "";
    }
  }
  if (nav.mimeTypes) {
    str += `|${nav.mimeTypes.length}`;
  }
  return crc32(new TextEncoder().encode(str || "0"));
}

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
    fp.webglVendor ?? "",
    fp.webglRenderer ?? "",
    String(fp.webgl2Hash ?? 0),
    String(fp.audioHash ?? 0),
    String(fp.fontsHash ?? 0),
    String(fp.pluginsHash ?? 0),
    fp.webdriver ? "1" : "0",
    String(fp.innerWidth ?? 0),
    String(fp.innerHeight ?? 0),
    String(fp.outerWidth ?? 0),
    String(fp.outerHeight ?? 0),
  ];
  const str = parts.join("|");
  return new TextEncoder().encode(str);
}

const MAX_TIMESTAMP_DRIFT_MS = 120_000;
const USER_AGENT_MISMATCH = 0.35;
const LANGUAGE_MISMATCH = 0.25;
const TIMESTAMP_DRIFT = 0.3;
const ENTROPY_MISMATCH = 0.4;

export function crossReferenceEntropy(
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

  const serverNow = Date.now();
  const drift = Math.abs(serverNow - clientTimestamp);
  if (drift > MAX_TIMESTAMP_DRIFT_MS) {
    score += TIMESTAMP_DRIFT;
    reasons.push("timestamp_drift");
  }

  if (fingerprint.webdriver) {
    score += 0.5;
    reasons.push("webdriver_detected");
  }

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

const RATE_LIMIT = 30;
const SERVER_MIN_INTERVAL_MS = 300;

export function analyseBehaviour(events: BehaviourEvent[]): { score: number; flags: Partial<SuspiciousFlags> } {
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

  const tooFast = intervals.some((d) => d < SERVER_MIN_INTERVAL_MS);
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

export function computeFingerprintHash(fp: ClientFingerprint): string {
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

export class BehaviourTracker {
  private events: BehaviourEvent[] = [];
  private lastFingerprint: ClientFingerprint | null = null;

  record(type: string, payload?: Record<string, unknown>): void {
    this.events.push({
      type,
      timestamp: Date.now(),
      payload,
    });
    this.prune();
  }

  setFingerprint(fp: ClientFingerprint): void {
    this.lastFingerprint = fp;
  }

  private prune(): void {
    const cutoff = Date.now() - BEHAVIOUR_WINDOW_MS;
    this.events = this.events.filter((e) => e.timestamp >= cutoff);
  }

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

  getEvents(): BehaviourEvent[] {
    this.prune();
    return [...this.events];
  }

  clear(): void {
    this.events = [];
  }
}

let defaultTracker: BehaviourTracker | null = null;

export function getBehaviourTracker(): BehaviourTracker {
  if (!defaultTracker) defaultTracker = new BehaviourTracker();
  return defaultTracker;
}

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
