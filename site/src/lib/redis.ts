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

/** Get TTL of a key in seconds. Returns -1 if no expiry, -2 if key doesn't exist. */
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

export async function disconnect(): Promise<void> {
  if (client) {
    await client.close();
    client = null;
    globalForRedis.redis = null;
  }
}
