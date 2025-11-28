import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, AccessTokenPayload } from '../utils/jwt.js';
import { isTokenBlacklisted } from '../services/tokenBlacklist.js';
import { errorResponse, ErrorCodes } from '../utils/response.js';

declare global {
  namespace Express {
    interface Request {
      user?: AccessTokenPayload;
    }
  }
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    errorResponse(
      res,
      ErrorCodes.UNAUTHORIZED.code,
      'Missing or invalid authorization header',
      ErrorCodes.UNAUTHORIZED.status
    );
    return;
  }

  const token = authHeader.substring(7);

  try {
    const payload = verifyAccessToken(token);

    // Check if token is blacklisted
    if (payload.jti && await isTokenBlacklisted(payload.jti)) {
      errorResponse(
        res,
        ErrorCodes.INVALID_TOKEN.code,
        'Token has been revoked',
        ErrorCodes.UNAUTHORIZED.status
      );
      return;
    }

    req.user = payload;
    next();
  } catch (error) {
    if (error instanceof Error && error.name === 'TokenExpiredError') {
      errorResponse(
        res,
        ErrorCodes.TOKEN_EXPIRED.code,
        'Access token has expired',
        ErrorCodes.TOKEN_EXPIRED.status
      );
      return;
    }

    errorResponse(
      res,
      ErrorCodes.INVALID_TOKEN.code,
      'Invalid access token',
      ErrorCodes.UNAUTHORIZED.status
    );
  }
}
