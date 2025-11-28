import { redis } from '../config/redis.js';

export async function blacklistToken(jti: string, expiresInSeconds: number): Promise<void> {
  const key = `token:blacklist:${jti}`;
  await redis.setex(key, expiresInSeconds, '1');
}

export async function isTokenBlacklisted(jti: string): Promise<boolean> {
  const key = `token:blacklist:${jti}`;
  const result = await redis.get(key);
  return result !== null;
}
