import { NextRequest, NextResponse } from "next/server";
import { getRecentRequests } from "@/lib/redis";
import { logRouteRequest } from "@/lib/request-logger";

export async function GET(request: NextRequest) {
  await logRouteRequest(request, "/api/manager/requests");
  try {
    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get("page") ?? "1", 10));
    const limit = Math.min(100, Math.max(10, parseInt(searchParams.get("limit") ?? "50", 10)));
    const { requests, total } = await getRecentRequests(limit, page);
    return NextResponse.json({ requests, total, page, limit });
  } catch (error) {
    console.error("Manager requests API error:", error);
    return NextResponse.json(
      { error: "Failed to fetch requests" },
      { status: 500 }
    );
  }
}
