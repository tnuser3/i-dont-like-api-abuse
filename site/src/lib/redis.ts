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

/** Expiry options - use ONE of: exSeconds, exMs, exAt, pxAt */
export type ExpiryOptions =
  | { exSeconds: number }
  | { exMs: number }
  | { exAt: Date | number }
  | { pxAt: Date | number };

/** Set a key with optional expiry. Value is JSON-stringified. */
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

/** Get a key. Returns parsed JSON or null if not found. */
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

/** Delete a key. */
export async function del(key: string): Promise<void> {
  const c = await getClient();
  await c.del(key);
}

/** Set expiry on an existing key (in seconds). */
export async function expire(key: string, seconds: number): Promise<void> {
  const c = await getClient();
  await c.expire(key, seconds);
}

/** Set expiry on an existing key (in milliseconds). */
export async function expireMs(key: string, ms: number): Promise<void> {
  const c = await getClient();
  await c.pExpire(key, ms);
}

/** Set expiry at a specific timestamp (Unix seconds). */
export async function expireAt(key: string, unixSeconds: number | Date): Promise<void> {
  const c = await getClient();
  const sec = unixSeconds instanceof Date ? Math.floor(unixSeconds.getTime() / 1000) : unixSeconds;
  await c.expireAt(key, sec);
}

/** Get TTL of a key in seconds. Returns -1 if no expiry, -2 if key doesn't exist. */
export async function ttl(key: string): Promise<number> {
  const c = await getClient();
  return c.ttl(key);
}

/** Check if key exists. */
export async function exists(key: string): Promise<boolean> {
  const c = await getClient();
  return (await c.exists(key)) === 1;
}

/** Disconnect the Redis client (e.g. for graceful shutdown). */
export async function disconnect(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    globalForRedis.redis = null;
  }
}
