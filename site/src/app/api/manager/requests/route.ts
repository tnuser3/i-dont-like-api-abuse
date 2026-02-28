import { NextRequest, NextResponse } from "next/server";
import { getRecentRequests } from "@/lib/redis";
import { logRouteRequest } from "@/lib/request-logger";

export async function GET(request: NextRequest) {
  await logRouteRequest(request, "/api/manager/requests");
  try {
    const limit = 200;
    const requests = await getRecentRequests(limit);
    return NextResponse.json({ requests });
  } catch (error) {
    console.error("Manager requests API error:", error);
    return NextResponse.json(
      { error: "Failed to fetch requests" },
      { status: 500 }
    );
  }
}
