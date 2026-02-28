import { createClient, type RedisClientType } from "redis";

const globalForRedis = globalThis as unknown as { redis: RedisClientType | null };

function getRedisClient(): RedisClientType {
  if (globalForRedis.redis) {
    return globalForRedis.redis;
  }

  const url = process.env.REDIS_URL ?? "redis://localhost:6379";
  const client = createClient({ url })
    .on("error", (err: unknown) => console.error("Redis Client Error", err));

  globalForRedis.redis = client as RedisClientType;
  return globalForRedis.redis;
}

let client: RedisClientType | null = null;

async function getClient(): Promise<RedisClientType> {
  if (!client) {
    client = getRedisClient();
    await client.connect();
  }
  return client;
}

export type ExpiryOptions =
  | { exSeconds: number }
  | { exMs: number }
  | { exAt: Date | number }
  | { pxAt: Date | number };

export async function set<T>(
  key: string,
  value: T,
  expiry?: ExpiryOptions
): Promise<void> {
  const c = await getClient();
  const serialized = JSON.stringify(value);

  if (!expiry) {
    await c.set(key, serialized);
    return;
  }

  if ("exSeconds" in expiry) {
    await c.set(key, serialized, { EX: expiry.exSeconds });
  } else if ("exMs" in expiry) {
    await c.set(key, serialized, { PX: expiry.exMs });
  } else if ("exAt" in expiry) {
    const unix = expiry.exAt instanceof Date ? Math.floor(expiry.exAt.getTime() / 1000) : expiry.exAt;
    await c.set(key, serialized, { EXAT: unix });
  } else {
    const unixMs = expiry.pxAt instanceof Date ? expiry.pxAt.getTime() : expiry.pxAt;
    await c.set(key, serialized, { PXAT: unixMs });
  }
}

export async function get<T>(key: string): Promise<T | null> {
  const c = await getClient();
  const value = await c.get(key);
  if (value === null) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return value as unknown as T;
  }
}

export async function del(key: string): Promise<void> {
  const c = await getClient();
  await c.del(key);
}

export async function getAndDel<T>(key: string): Promise<T | null> {
  const c = await getClient();
  const value = await c.get(key);
  if (value === null) return null;
  await c.del(key);
  try {
    return JSON.parse(value) as T;
  } catch {
    return value as unknown as T;
  }
}

export async function expire(key: string, seconds: number): Promise<void> {
  const c = await getClient();
  await c.expire(key, seconds);
}

export async function expireMs(key: string, ms: number): Promise<void> {
  const c = await getClient();
  await c.pExpire(key, ms);
}

export async function expireAt(key: string, unixSeconds: number | Date): Promise<void> {
  const c = await getClient();
  const sec = unixSeconds instanceof Date ? Math.floor(unixSeconds.getTime() / 1000) : unixSeconds;
  await c.expireAt(key, sec);
}

export async function ttl(key: string): Promise<number> {
  const c = await getClient();
  return c.ttl(key);
}

export async function exists(key: string): Promise<boolean> {
  const c = await getClient();
  return (await c.exists(key)) === 1;
}

export async function sAdd(key: string, ...members: string[]): Promise<number> {
  const c = await getClient();
  return c.sAdd(key, members);
}

export async function sMembers(key: string): Promise<string[]> {
  const c = await getClient();
  return c.sMembers(key);
}

export async function sCard(key: string): Promise<number> {
  const c = await getClient();
  return c.sCard(key);
}

export async function sRem(key: string, ...members: string[]): Promise<number> {
  const c = await getClient();
  return c.sRem(key, members);
}

export async function scanKeys(pattern: string, maxKeys = 1000): Promise<string[]> {
  const c = await getClient();
  const keys: string[] = [];
  let cursor: number | string = 0;
  do {
    const result = await c.scan(cursor.toString(), { MATCH: pattern, COUNT: 100 });
    cursor = typeof result.cursor === "string" ? parseInt(result.cursor, 10) : Number(result.cursor);
    keys.push(...(result.keys ?? []));
    if (keys.length >= maxKeys) break;
  } while (cursor !== 0);
  return keys.slice(0, maxKeys);
}

const REQUESTS_KEY = "manager:requests";
const MAX_REQUESTS = 500;

export async function logRequest(entry: Record<string, unknown>): Promise<void> {
  const c = await getClient();
  await c.lPush(REQUESTS_KEY, JSON.stringify(entry));
  await c.lTrim(REQUESTS_KEY, 0, MAX_REQUESTS - 1);
}

export async function getRecentRequests(
  limit = 50,
  page = 1
): Promise<{ requests: Record<string, unknown>[]; total: number }> {
  const c = await getClient();
  const total = await c.lLen(REQUESTS_KEY);
  const start = (page - 1) * limit;
  const stop = start + limit - 1;
  if (start >= total) {
    return { requests: [], total };
  }
  const raw = await c.lRange(REQUESTS_KEY, start, stop);
  const requests: Record<string, unknown>[] = [];
  for (const s of raw) {
    try {
      requests.push(JSON.parse(s) as Record<string, unknown>);
    } catch {
      requests.push({ raw: s });
    }
  }
  return { requests, total };
}

export async function disconnect(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    globalForRedis.redis = null;
  }
}
