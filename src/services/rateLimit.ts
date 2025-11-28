import { redis } from '../config/redis.js';
import { rateLimitConfig } from '../config/index.js';

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

type RateLimitAction = 'login' | 'signup';

export async function checkRateLimit(
  action: RateLimitAction,
  identifier: string
): Promise<RateLimitResult> {
  const config = rateLimitConfig[action];
  const key = `rate_limit:${action}:${identifier}`;
  const now = Date.now();
  const windowStart = now - config.windowMs;

  // Remove old entries outside the window
  await redis.zremrangebyscore(key, 0, windowStart);

  // Get current count
  const currentCount = await redis.zcard(key);

  if (currentCount >= config.maxRequests) {
    const oldestRequest = await redis.zrange(key, 0, 0, 'WITHSCORES');
    const resetAt = oldestRequest.length >= 2 
      ? parseInt(oldestRequest[1], 10) + config.windowMs 
      : now + config.windowMs;
    
    return { 
      allowed: false, 
      remaining: 0, 
      resetAt 
    };
  }

  // Add new request
  await redis.zadd(key, now, `${now}:${Math.random()}`);
  await redis.expire(key, Math.ceil(config.windowMs / 1000));

  return {
    allowed: true,
    remaining: config.maxRequests - currentCount - 1,
    resetAt: now + config.windowMs,
  };
}

export async function resetRateLimit(action: RateLimitAction, identifier: string): Promise<void> {
  const key = `rate_limit:${action}:${identifier}`;
  await redis.del(key);
}
