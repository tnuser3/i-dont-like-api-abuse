import { NextRequest } from "next/server";
import { logRequest } from "./redis";

export async function logRouteRequest(
  request: NextRequest,
  path: string,
  visitorId?: string
): Promise<void> {
  try {
    const id = visitorId ?? request.headers.get("x-visitor-id") ?? undefined;
    await logRequest({
      path,
      method: request.method,
      timestamp: Date.now(),
      userAgent: request.headers.get("user-agent") ?? undefined,
      referer: request.headers.get("referer") ?? undefined,
      ip: request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? undefined,
      visitorId: id || undefined,
    });
  } catch {}
}
