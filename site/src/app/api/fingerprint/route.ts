import { NextRequest, NextResponse } from "next/server";
import { storeFingerprint, verifySignedFingerprint } from "@/lib/fingerprint";
import { logRouteRequest } from "@/lib/request-logger";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const visitorId = (body?.payload as { visitorId?: string })?.visitorId;

    let payload;
    try {
      payload = await verifySignedFingerprint(body);
    } catch (err) {
      await logRouteRequest(request, "/api/fingerprint", visitorId);
      const msg = err instanceof Error ? err.message : "Verification failed";
      return NextResponse.json({ error: msg }, { status: 401 });
    }

    await logRouteRequest(request, "/api/fingerprint", payload.visitorId);
    const result = await storeFingerprint(payload);

    return NextResponse.json(result);
  } catch (error) {
    console.error("Fingerprint route error:", error);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
