import { NextRequest, NextResponse } from "next/server";
import { verifyChallengeToken } from "@/lib/jwt-challenge";
import { getAndDel } from "@/lib/redis";
import { logRouteRequest } from "@/lib/request-logger";
import { decryptRequestBody } from "@/lib/key-session-server";
import { processRequest } from "@/lib/request-risk-assessor";

export async function POST(request: NextRequest) {
  const risk = await processRequest(request);
  if (risk.blocked) return risk.response;
  await logRouteRequest(request, "/api/challenge/verify");
  try {
    const raw = await request.json();
    if (!raw || typeof raw !== "object") {
      return NextResponse.json({ ok: false, error: "Invalid payload" }, { status: 400 });
    }
    const envelope = raw as { id?: string; body?: string };
    if (typeof envelope.id !== "string" || typeof envelope.body !== "string") {
      return NextResponse.json(
        { ok: false, error: "id and body required (encrypted)" },
        { status: 400 }
      );
    }

    let body: { token?: string; solved?: number | string };
    try {
      body = (await decryptRequestBody(envelope.id, envelope.body)) as typeof body;
    } catch {
      return NextResponse.json(
        { ok: false, error: "Decryption failed" },
        { status: 400 }
      );
    }

    const { token, solved } = body;

    if (typeof token !== "string" || !token) {
      return NextResponse.json(
        { ok: false, error: "token required" },
        { status: 400 }
      );
    }

    const solvedRaw = typeof solved === "number" ? solved : parseInt(String(solved), 10);
    if (isNaN(solvedRaw) || !Number.isInteger(solvedRaw) || solvedRaw < -0x80000000 || solvedRaw > 0xffffffff) {
      return NextResponse.json(
        { ok: false, error: "solved must be a uint32 (0–4294967295)" },
        { status: 400 }
      );
    }
    const solvedNum = solvedRaw >>> 0;

    let challengeId: string;
    try {
      const payload = await verifyChallengeToken(token);
      challengeId = payload.challengeId;
    } catch {
      return NextResponse.json(
        { ok: false, error: "Invalid or expired token" },
        { status: 401 }
      );
    }

    const expected = await getAndDel<number>(`challenge:${challengeId}`);
    if (expected === null) {
      return NextResponse.json(
        { ok: false, error: "Challenge not found or already used" },
        { status: 400 }
      );
    }

    if (solvedNum !== expected) {
      return NextResponse.json({ ok: false });
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("Challenge verify error:", error);
    return NextResponse.json(
      { ok: false, error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
