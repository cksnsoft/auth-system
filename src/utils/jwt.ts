import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { jwtConfig } from '../config/index.js';

export interface AccessTokenPayload extends JwtPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  scope: string;
  jti: string;
}

export interface IdTokenPayload extends JwtPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
}

interface UserForToken {
  id: string;
  email: string;
  emailVerified: boolean;
  profile?: {
    givenName?: string | null;
    familyName?: string | null;
    pictureUrl?: string | null;
    locale?: string | null;
  } | null;
}

export function generateAccessToken(user: UserForToken): string {
  const payload: Omit<AccessTokenPayload, 'iat' | 'exp' | 'iss' | 'aud'> = {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    scope: 'read write',
    jti: uuidv4(),
  };

  const options: SignOptions = {
    algorithm: 'RS256',
    expiresIn: jwtConfig.accessTokenExpiresIn,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
  };

  return jwt.sign(payload, jwtConfig.privateKey, options);
}

export function generateIdToken(user: UserForToken): string {
  const payload: Omit<IdTokenPayload, 'iat' | 'exp' | 'iss' | 'aud'> = {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    name: user.profile 
      ? [user.profile.givenName, user.profile.familyName].filter(Boolean).join(' ') || undefined 
      : undefined,
    given_name: user.profile?.givenName ?? undefined,
    family_name: user.profile?.familyName ?? undefined,
    picture: user.profile?.pictureUrl ?? undefined,
    locale: user.profile?.locale ?? undefined,
  };

  const options: SignOptions = {
    algorithm: 'RS256',
    expiresIn: jwtConfig.accessTokenExpiresIn,
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
  };

  return jwt.sign(payload, jwtConfig.privateKey, options);
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, jwtConfig.publicKey, {
    algorithms: ['RS256'],
    issuer: jwtConfig.issuer,
    audience: jwtConfig.audience,
  }) as AccessTokenPayload;
}

export function decodeToken(token: string): JwtPayload | null {
  return jwt.decode(token) as JwtPayload | null;
}

export function getTokenExpirationSeconds(expiresIn: string): number {
  const match = expiresIn.match(/^(\d+)([smhd])$/);
  if (!match) return 3600;
  
  const value = parseInt(match[1], 10);
  const unit = match[2];
  
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 60 * 60;
    case 'd': return value * 24 * 60 * 60;
    default: return 3600;
  }
}
