import { NextRequest, NextResponse } from "next/server";
import { scanKeys, get } from "@/lib/redis";
import type { StoredDevice } from "@/lib/fingerprint";
import { logRouteRequest } from "@/lib/request-logger";
import { processRequest } from "@/lib/request-risk-assessor";

const FP_DEV_PREFIX = "fp:dev:";

export async function GET(request: NextRequest) {
  const risk = await processRequest(request);
  if (risk.blocked) return risk.response;
  await logRouteRequest(request, "/api/manager/fingerprints");
  try {
    const keys = await scanKeys(`${FP_DEV_PREFIX}*`, 500);
    const fingerprints: (StoredDevice & { visitorId: string })[] = [];

    for (const key of keys) {
      const visitorId = key.replace(FP_DEV_PREFIX, "");
      const device = await get<StoredDevice>(key);
      if (device) {
        fingerprints.push({ ...device, visitorId });
      }
    }

    fingerprints.sort((a, b) => b.lastSeen - a.lastSeen);

    return NextResponse.json({ fingerprints });
  } catch (error) {
    console.error("Manager fingerprints API error:", error);
    return NextResponse.json(
      { error: "Failed to fetch fingerprints" },
      { status: 500 }
    );
  }
}
