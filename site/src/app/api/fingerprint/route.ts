import { NextRequest, NextResponse } from "next/server";
import { storeFingerprint, verifySignedFingerprint } from "@/lib/fingerprint";
import { logRouteRequest } from "@/lib/request-logger";

export async function POST(request: NextRequest) {
  await logRouteRequest(request, "/api/fingerprint");
  try {
    const body = await request.json();

    let payload;
    try {
      payload = await verifySignedFingerprint(body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Verification failed";
      return NextResponse.json({ error: msg }, { status: 401 });
    }

    const result = await storeFingerprint(payload);

    return NextResponse.json(result);
  } catch (error) {
    console.error("Fingerprint route error:", error);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
