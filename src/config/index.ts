import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  
  DATABASE_URL: z.string(),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  
  JWT_PRIVATE_KEY: z.string(),
  JWT_PUBLIC_KEY: z.string(),
  JWT_ACCESS_TOKEN_EXPIRES_IN: z.string().default('1h'),
  JWT_REFRESH_TOKEN_EXPIRES_IN: z.string().default('30d'),
  JWT_ISSUER: z.string().default('https://auth.example.com'),
  JWT_AUDIENCE: z.string().default('https://api.example.com'),
  
  FRONTEND_URL: z.string().default('http://localhost:3001'),
  
  RATE_LIMIT_LOGIN_WINDOW_MS: z.string().transform(Number).default('300000'),
  RATE_LIMIT_LOGIN_MAX_REQUESTS: z.string().transform(Number).default('5'),
  RATE_LIMIT_SIGNUP_WINDOW_MS: z.string().transform(Number).default('3600000'),
  RATE_LIMIT_SIGNUP_MAX_REQUESTS: z.string().transform(Number).default('10'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;

export const jwtConfig = {
  privateKey: config.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
  publicKey: config.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
  accessTokenExpiresIn: config.JWT_ACCESS_TOKEN_EXPIRES_IN,
  refreshTokenExpiresIn: config.JWT_REFRESH_TOKEN_EXPIRES_IN,
  issuer: config.JWT_ISSUER,
  audience: config.JWT_AUDIENCE,
};

export const rateLimitConfig = {
  login: {
    windowMs: config.RATE_LIMIT_LOGIN_WINDOW_MS,
    maxRequests: config.RATE_LIMIT_LOGIN_MAX_REQUESTS,
  },
  signup: {
    windowMs: config.RATE_LIMIT_SIGNUP_WINDOW_MS,
    maxRequests: config.RATE_LIMIT_SIGNUP_MAX_REQUESTS,
  },
};
