import { NextRequest, NextResponse } from "next/server";
import { verifyChallengeToken } from "@/lib/jwt-challenge";
import { getAndDel } from "@/lib/redis";
import { logRouteRequest } from "@/lib/request-logger";

export async function POST(request: NextRequest) {
  await logRouteRequest(request, "/api/challenge/verify");
  try {
    const body = await request.json();
    const { token, solved } = body as {
      token?: string;
      solved?: number | string;
    };

    if (typeof token !== "string" || !token) {
      return NextResponse.json(
        { ok: false, error: "token required" },
        { status: 400 }
      );
    }

    const raw = typeof solved === "number" ? solved : parseInt(String(solved), 10);
    if (isNaN(raw) || !Number.isInteger(raw) || raw < -0x80000000 || raw > 0xffffffff) {
      return NextResponse.json(
        { ok: false, error: "solved must be a uint32 (0–4294967295)" },
        { status: 400 }
      );
    }
    const solvedNum = raw >>> 0;

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
