import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { get, set } from "./redis";

const DEBUG = process.env.RISK_DEBUG === "1" || process.env.DEBUG?.includes("risk");
const log = (...args: unknown[]) => {
  if (DEBUG) console.debug("[risk]", ...args);
};

function seededOffset(seed: number, range: number): number {
  const n = (seed * 1103515245 + 12345) & 0x7fffffff;
  return (n % (range * 2 + 1)) - range;
}

function randomInRange(lo: number, hi: number): number {
  return Math.floor(Math.random() * (hi - lo + 1)) + lo;
}

const PREFIX = "risk:";
const RL_PREFIX = `${PREFIX}rl:`;
const REQ_PREFIX = `${PREFIX}req:`;
const ASN_PREFIX = `${PREFIX}asn:`;
const IP_ASN_PREFIX = `${PREFIX}ipasn:`;
const VIOLATION_WINDOW_MS = 2 * 60 * 1000;
const STRIKES_FOR_ESCALATION = 6;
const BASE_BLOCK_SEC = 8;
const MAX_BLOCK_SEC = 25;
const BLOCK_INCREMENT_SEC = 3;
const BLOCK_JITTER_SEC = 2;
const RATE_TIERS: { limit: number; limitJitter: number; windowMs: number; windowJitter: number }[] = [
  { limit: 60, limitJitter: 15, windowMs: 30_000, windowJitter: 5000 },
  { limit: 80, limitJitter: 20, windowMs: 45_000, windowJitter: 5000 },
  { limit: 70, limitJitter: 20, windowMs: 60_000, windowJitter: 5000 },
];
const ASN_BLOCK_THRESHOLD = 5;
const ASN_SCORE_PER_BLOCKED_IP = 0.1;
const MAX_ASN_SCORE = 0.2;
const ASN_BASE_SCORE_MULTIPLIER = 0.2;
const ASN_BASE_SCORES_PATH = "data/asn-base-scores.json";

let asnBaseScoresCache: Record<string, number> | null = null;

async function getAsnBaseScores(): Promise<Record<string, number>> {
  if (asnBaseScoresCache) return asnBaseScoresCache;
  try {
    const root = process.cwd();
    const raw = await readFile(join(root, ASN_BASE_SCORES_PATH), "utf-8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const scores: Record<string, number> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (k.startsWith("_")) continue;
      const n = typeof v === "number" ? v : parseFloat(String(v));
      if (!isNaN(n) && n >= 0) {
        scores[k] = Math.min(MAX_ASN_SCORE, n * ASN_BASE_SCORE_MULTIPLIER);
      }
    }
    asnBaseScoresCache = scores;
    return scores;
  } catch {
    asnBaseScoresCache = {};
    return {};
  }
}
export const RISK_BLOCK_THRESHOLD = 0.45;

export interface RiskRequestInput {
  ip: string;
  userAgent: string | null;
  origin: string | null;
  referer: string | null;
  secChUa?: string | null;
  via?: string | null;
}

export interface RiskAssessment {
  score: number;
  blocked: boolean;
  blockUntil?: number;
  reasons: string[];
}

const BOT_PATTERNS = [
  /headlesschrome/i,
  /headlesschromeselenium/i,
  /chromedriver/i,
  /headless/i,
  /swiftshader/i,
  /llvmpipe/i,
  /mesa\s+offscreen/i,
  /bot/i,
  /crawl/i,
  /spider/i,
  /curl/i,
  /wget/i,
  /python-requests/i,
  /python\//i,
  /java\//i,
  /go-http/i,
  /php\//i,
  /scrapy/i,
  /axios/i,
  /postman/i,
  /insomnia/i,
  /httpie/i,
  /^http\//i,
  /^node\s/i,
  /^okhttp/i,
  /phantom/i,
  /puppeteer/i,
  /playwright/i,
  /selenium/i,
  /__webdriver/i,
  /cdc_/i,
  /\$cdc_/i,
  /\$wdc_/i,
  /webdriver/i,
  /chrome-lighthouse/i,
  /chromium\/[0-9]+\.0\s+headless/i,
  /socks[45]/i,
];

const LEGITIMATE_PATTERNS = [
  /mozilla/i,
  /chrome/i,
  /safari/i,
  /firefox/i,
  /edg(e|a)/i,
  /opera/i,
  /brave/i,
];

function assessUserAgent(ua: string | null): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;
  if (!ua || ua.length === 0) {
    score += 0.5;
    reasons.push("ua_empty");
    log("assessUserAgent: empty ua", { score, reasons });
    return { score, reasons };
  }
  if (ua.length < 10) {
    score += 0.2;
    reasons.push("ua_too_short");
  }
  for (const p of BOT_PATTERNS) {
    if (p.test(ua)) {
      score += 0.65;
      reasons.push("ua_bot_like");
      break;
    }
  }
  let hasLegit = false;
  for (const p of LEGITIMATE_PATTERNS) {
    if (p.test(ua)) {
      hasLegit = true;
      break;
    }
  }
  if (!hasLegit && ua.length > 20) {
    score += 0.2;
    reasons.push("ua_no_browser_token");
  }
  log("assessUserAgent", { ua: ua.slice(0, 80), score, reasons });
  return { score, reasons };
}

function assessOrigin(origin: string | null): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;
  try {
    if (!origin) {
      reasons.push("origin_missing");
      return { score, reasons };
    }
    const u = new URL(origin);
    if (u.protocol !== "https:" && u.protocol !== "http:") {
      score += 0.2;
      reasons.push("origin_unusual_protocol");
    }
  } catch {
    score += 0.3;
    reasons.push("origin_invalid");
  }
  log("assessOrigin", { origin, score, reasons });
  return { score, reasons };
}

function assessReferer(referer: string | null): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;
  if (!referer || referer.length === 0) {
    score += 0.1;
    reasons.push("referer_missing");
  }
  log("assessReferer", { referer: referer ?? null, score, reasons });
  return { score, reasons };
}

function assessSecChUa(secChUa: string | null | undefined): { score: number; reasons: string[] } {
  if (!secChUa || secChUa.length === 0) return { score: 0, reasons: [] };
  if (/headlesschrome/i.test(secChUa)) {
    return { score: 0.5, reasons: ["sec_ch_ua_headless"] };
  }
  return { score: 0, reasons: [] };
}

function assessVia(via: string | null | undefined): { score: number; reasons: string[] } {
  if (!via || via.length === 0) return { score: 0, reasons: [] };
  const proxies = via.toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
  if (proxies.length >= 3) {
    return { score: 0.15, reasons: ["via_proxy_chain"] };
  }
  return { score: 0, reasons: [] };
}

const SUSPICIOUS_WEBGL_RENDERERS = [
  /swiftshader/i,
  /llvmpipe/i,
  /mesa\s+offscreen/i,
  /software\s+renderer/i,
  /mesa\s+software/i,
  /virgl/i,
  /lavapipe/i,
  /google\s+swiftshader/i,
  /llvmpipe.*gallium/i,
];

const WEBGL_ABSENT_OR_DISABLED = [
  /^\s*$/,
  /^unknown$/i,
  /^none$/i,
  /^n\/a$/i,
  /disabled/i,
  /blocked/i,
  /unavailable/i,
  /not available/i,
  /not supported/i,
  /webgl\s+disabled/i,
];

export function assessFingerprintComponents(
  components: Record<string, { value?: unknown; error?: unknown; duration?: number }>,
  webglVendor: string | null | undefined
): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  let screenFrameAllZeros = false;
  const screenFrameComp = components["screenFrame"];
  if (screenFrameComp?.value !== undefined) {
    let arr: number[] | null = null;
    const v = screenFrameComp.value;
    if (typeof v === "string") {
      const m = v.match(/^\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]$/);
      if (m) arr = [parseFloat(m[1]!), parseFloat(m[2]!), parseFloat(m[3]!), parseFloat(m[4]!)];
    } else if (Array.isArray(v) && v.length >= 4) {
      arr = v.slice(0, 4).map((x) => (typeof x === "number" ? x : parseFloat(String(x))));
    }
    screenFrameAllZeros = !!arr && arr.every((n) => n === 0);
  }

  const vendor = String(webglVendor ?? "").trim();
  const isGoogleInc = /^Google\s*Inc\.?$/i.test(vendor);

  if (screenFrameAllZeros && isGoogleInc) {
    score += 0.5;
    reasons.push("chomium_screen_frame");
  }

  return { score, reasons };
}

export function assessWebGLRenderer(renderer: string | null | undefined): { score: number; reasons: string[] } {
  const s = typeof renderer === "string" ? renderer.trim() : "";
  if (!s) return { score: 0, reasons: [] };
  for (const p of WEBGL_ABSENT_OR_DISABLED) {
    if (p.test(s)) return { score: 0, reasons: [] };
  }
  for (const p of SUSPICIOUS_WEBGL_RENDERERS) {
    if (p.test(s)) {
      return { score: 0.25, reasons: ["webgl_suspicious_renderer"] };
    }
  }
  return { score: 0, reasons: [] };
}

export function assessHeaders(input: RiskRequestInput): { score: number; reasons: string[] } {
  const ua = assessUserAgent(input.userAgent);
  const origin = assessOrigin(input.origin);
  const referer = assessReferer(input.referer);
  const secChUa = assessSecChUa(input.secChUa);
  const via = assessVia(input.via);
  const score = Math.min(1, ua.score + origin.score + referer.score + secChUa.score + via.score);
  const reasons = [...ua.reasons, ...origin.reasons, ...referer.reasons, ...secChUa.reasons, ...via.reasons];
  log("assessHeaders", { score, reasons, breakdown: { ua: ua.score, origin: origin.score, referer: referer.score, secChUa: secChUa.score, via: via.score } });
  return { score, reasons };
}

async function getAsnForIp(ip: string): Promise<string> {
  const cacheKey = `${IP_ASN_PREFIX}${ip}`;
  const cached = await get<string>(cacheKey);
  if (cached) {
    log("getAsnForIp: cache hit", { ip, asn: cached });
    return cached;
  }
  log("getAsnForIp: cache miss, fetching", { ip });
  try {
    const res = await fetch(
      `https://ip-api.com/json/${ip}?fields=as`,
      { signal: AbortSignal.timeout(2000) }
    );
    if (!res.ok) throw new Error("Lookup failed");
    const data = (await res.json()) as { as?: string };
    const asStr = data.as;
    let asn = "unknown";
    if (asStr && typeof asStr === "string") {
      const m = asStr.match(/^AS(\d+)/);
      asn = m ? `AS${m[1]}` : asStr.split(" ")[0] ?? "unknown";
    }
    await set(cacheKey, asn, { exSeconds: 86400 });
    log("getAsnForIp: fetched", { ip, asn });
    return asn;
  } catch (err) {
    const parts = ip.replace(/^::ffff:/, "").split(".");
    const fallback = parts.length >= 3 ? `subnet:${parts[0]}.${parts[1]}.${parts[2]}` : `ip:${ip}`;
    await set(cacheKey, fallback, { exSeconds: 3600 });
    log("getAsnForIp: fetch failed, using fallback", { ip, fallback, err });
    return fallback;
  }
}

async function getAsnScore(asn: string): Promise<number> {
  const baseScores = await getAsnBaseScores();
  let baseScore = baseScores[asn] ?? 0;
  const key = `${ASN_PREFIX}${asn}`;
  const raw = await get<{ blockedCount: number }>(key);
  let dynamicScore = 0;
  if (raw && raw.blockedCount >= ASN_BLOCK_THRESHOLD) {
    dynamicScore = Math.min(
      MAX_ASN_SCORE - baseScore,
      (raw.blockedCount - ASN_BLOCK_THRESHOLD + 1) * ASN_SCORE_PER_BLOCKED_IP
    );
  }
  const score = Math.min(MAX_ASN_SCORE, baseScore + dynamicScore);
  log("getAsnScore", { asn, baseScore, blockedCount: raw?.blockedCount ?? 0, dynamicScore, score });
  return score;
}

async function recordAsnBlock(asn: string): Promise<void> {
  const key = `${ASN_PREFIX}${asn}`;
  const raw = await get<{ blockedCount: number }>(key);
  const blockedCount = (raw?.blockedCount ?? 0) + 1;
  await set(key, { blockedCount }, { exSeconds: 86400 * 7 });
  log("recordAsnBlock", { asn, blockedCount });
}

interface RateLimitState {
  violations: number;
  lastViolations: number[];
  blockUntil: number;
  blockCount: number;
}

export async function checkRateLimit(ip: string): Promise<{
  allowed: boolean;
  blockUntil?: number;
  violations: number;
}> {
  const key = `${RL_PREFIX}${ip}`;
  const raw = await get<RateLimitState>(key);
  const now = Date.now();
  if (raw?.blockUntil && raw.blockUntil > now) {
    log("checkRateLimit: blocked (active)", { ip, blockUntil: raw.blockUntil, violations: raw.violations });
    return { allowed: false, blockUntil: raw.blockUntil, violations: raw.violations };
  }
  if (!raw) {
    log("checkRateLimit: allowed (no history)", { ip });
    return { allowed: true, violations: 0 };
  }
  const recentViolations = raw.lastViolations.filter((t) => now - t < VIOLATION_WINDOW_MS);
  const strikes = recentViolations.length;
  if (strikes >= STRIKES_FOR_ESCALATION) {
    const blockCount = raw.blockCount + 1;
    const base = Math.min(MAX_BLOCK_SEC, BASE_BLOCK_SEC + (blockCount - 1) * BLOCK_INCREMENT_SEC);
    const jitter = randomInRange(-BLOCK_JITTER_SEC, BLOCK_JITTER_SEC);
    const blockDurationSec = Math.max(5, Math.min(MAX_BLOCK_SEC, base + jitter));
    const blockUntil = now + blockDurationSec * 1000;
    await set(
      key,
      {
        violations: raw.violations,
        lastViolations: recentViolations.slice(-10),
        blockUntil,
        blockCount,
      } satisfies RateLimitState,
      { exSeconds: Math.ceil(blockDurationSec) + 300 }
    );
    log("checkRateLimit: re-blocking (strikes in window)", { ip, strikes, blockCount, blockDurationSec, blockUntil });
    return { allowed: false, blockUntil, violations: raw.violations };
  }
  log("checkRateLimit: allowed", { ip, violations: raw.violations, strikes });
  return { allowed: true, violations: raw.violations };
}

export async function enforceRequestRate(ip: string): Promise<{
  allowed: boolean;
  blockUntil?: number;
  count: number;
  limit: number;
  rateLimited?: boolean;
}> {
  const rl = await checkRateLimit(ip);
  if (!rl.allowed && rl.blockUntil) {
    log("enforceRequestRate: blocked (from checkRateLimit)", { ip, blockUntil: rl.blockUntil });
    return { allowed: false, blockUntil: rl.blockUntil, count: 0, limit: RATE_TIERS[0]!.limit };
  }
  const tier = Math.min(rl.violations, RATE_TIERS.length - 1);
  const { limit: baseLimit, limitJitter, windowMs } = RATE_TIERS[tier]!;
  const bucket = Math.floor(Date.now() / windowMs);
  const seed = (ip + tier + bucket).split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const limit = Math.max(5, baseLimit + seededOffset(seed, limitJitter));
  const key = `${REQ_PREFIX}${ip}:${tier}:${bucket}`;
  const raw = await get<number>(key);
  const count = (raw ?? 0) + 1;
  await set(key, count, { exSeconds: Math.ceil(windowMs / 1000) + 10 });
  if (count > limit) {
    log("enforceRequestRate: over limit", { ip, count, limit, baseLimit, violations: rl.violations, windowMs });
    await recordRateLimitViolation(ip);
    const rl2 = await checkRateLimit(ip);
    log("enforceRequestRate: rate limited, blocking", { ip, blockUntil: rl2.blockUntil });
    return {
      allowed: false,
      blockUntil: rl2.blockUntil,
      count,
      limit,
      rateLimited: true,
    };
  }
  log("enforceRequestRate: allowed", { ip, count, limit, windowMs });
  return { allowed: true, count, limit };
}

export async function recordRateLimitViolation(ip: string): Promise<void> {
  const key = `${RL_PREFIX}${ip}`;
  const raw = await get<RateLimitState>(key);
  const now = Date.now();
  const lastViolations = raw?.lastViolations ?? [];
  const newViolations = [...lastViolations.filter((t) => now - t < VIOLATION_WINDOW_MS), now];
  const blockCount = raw?.blockCount ?? 0;
  const strikes = newViolations.length;
  let blockUntil = raw?.blockUntil ?? 0;
  log("recordRateLimitViolation", { ip, strikes, blockCount, previousViolations: raw?.violations ?? 0 });
  if (strikes >= STRIKES_FOR_ESCALATION) {
    const nextBlockCount = blockCount + 1;
    const base = Math.min(MAX_BLOCK_SEC, BASE_BLOCK_SEC + (nextBlockCount - 1) * BLOCK_INCREMENT_SEC);
    const jitter = randomInRange(-BLOCK_JITTER_SEC, BLOCK_JITTER_SEC);
    const blockDurationSec = Math.max(5, Math.min(MAX_BLOCK_SEC, base + jitter));
    blockUntil = now + blockDurationSec * 1000;
    await set(
      key,
      {
        violations: (raw?.violations ?? 0) + 1,
        lastViolations: newViolations.slice(-10),
        blockUntil,
        blockCount: nextBlockCount,
      } satisfies RateLimitState,
      { exSeconds: Math.ceil(blockDurationSec) + 300 }
    );
    log("recordRateLimitViolation: applied block", { ip, nextBlockCount, blockDurationSec, blockUntil });
  } else {
    await set(
      key,
      {
        violations: (raw?.violations ?? 0) + 1,
        lastViolations: newViolations.slice(-10),
        blockUntil: blockUntil && blockUntil > now ? blockUntil : 0,
        blockCount,
      } satisfies RateLimitState,
      { exSeconds: 86400 }
    );
    log("recordRateLimitViolation: strike recorded (no block yet)", { ip, strikes, needed: STRIKES_FOR_ESCALATION });
  }
  const asn = await getAsnForIp(ip);
  await recordAsnBlock(asn);
}

export function extractRiskInput(request: NextRequest): RiskRequestInput {
  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "unknown";
  const input: RiskRequestInput = {
    ip,
    userAgent: request.headers.get("user-agent"),
    origin: request.headers.get("origin"),
    referer: request.headers.get("referer"),
    secChUa: request.headers.get("sec-ch-ua"),
    via: request.headers.get("via"),
  };
  log("extractRiskInput", input);
  return input;
}

export async function assessBody(input: NextRequest): Promise<{ score: number; reasons: string[] }> {
  const body = await input.json();
  if (!body || typeof body !== "object") return { score: 0, reasons: [] };
  
  return { score: 0, reasons: [] };
}

export async function assessRequest(input: RiskRequestInput, request: NextRequest): Promise<RiskAssessment> {
  const headerResult = assessHeaders(input);

  const rl = await checkRateLimit(input.ip);
  const asn = await getAsnForIp(input.ip);
  const asnScore = await getAsnScore(asn);
  const totalScore = Math.min(1, headerResult.score + asnScore);
  if (!rl.allowed && rl.blockUntil) {
    const out = {
      score: totalScore,
      blocked: true as const,
      blockUntil: rl.blockUntil,
      reasons: [...headerResult.reasons, "rate_limit_blocked"],
    };
    log("assessRequest: blocked (rate limit)", { ip: input.ip, ...out, asn, asnScore });
    return out;
  }
  const out = {
    score: totalScore,
    blocked: false as const,
    reasons: headerResult.reasons,
  };
  log("assessRequest: allowed", { ip: input.ip, ...out, asn, asnScore, headerScore: headerResult.score });
  return out;
}

export interface ProcessRequestResult {
  blocked: true;
  response: NextResponse;
}
export interface ProcessRequestAllowed {
  blocked: false;
  input: RiskRequestInput;
  assessment: RiskAssessment;
}

export async function processRequest(
  request: NextRequest
): Promise<ProcessRequestResult | ProcessRequestAllowed> {
  log("processRequest: start", { url: request.url });
  const input = extractRiskInput(request);
  const rateLimit = await enforceRequestRate(input.ip);
  if (!rateLimit.allowed && rateLimit.blockUntil) {
    const retryAfter = Math.ceil((rateLimit.blockUntil - Date.now()) / 1000);
    log("processRequest: BLOCKED (rate limit)", { ip: input.ip, retryAfter });
    return {
      blocked: true,
      response: NextResponse.json(
        { error: "Rate limited", retryAfter },
        { status: 429, headers: { "Retry-After": String(retryAfter) } }
      ),
    };
  }
  const assessment = await assessRequest(input, request);
  if (assessment.blocked && assessment.blockUntil) {
    const retryAfter = Math.ceil((assessment.blockUntil - Date.now()) / 1000);
    log("processRequest: BLOCKED (rate limit)", { ip: input.ip, retryAfter, reasons: assessment.reasons });
    return {
      blocked: true,
      response: NextResponse.json(
        { error: "Blocked", retryAfter, reasons: assessment.reasons },
        { status: 429, headers: { "Retry-After": String(retryAfter) } }
      ),
    };
  }
  if (assessment.score >= RISK_BLOCK_THRESHOLD) {
    log("processRequest: BLOCKED (risk score)", { ip: input.ip, score: assessment.score, reasons: assessment.reasons });
    return {
      blocked: true,
      response: NextResponse.json(
        { error: "Blocked", reasons: assessment.reasons },
        { status: 403 }
      ),
    };
  }
  log("processRequest: ALLOWED", { ip: input.ip, score: assessment.score, reasons: assessment.reasons });
  return { blocked: false, input, assessment };
}
