import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import * as authService from '../services/auth.js';
import { checkRateLimit } from '../services/rateLimit.js';
import { blacklistToken } from '../services/tokenBlacklist.js';
import { successResponse, errorResponse, ErrorCodes } from '../utils/response.js';
import { decodeToken, getTokenExpirationSeconds } from '../utils/jwt.js';
import { jwtConfig } from '../config/index.js';

const signupSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
  profile: z.object({
    givenName: z.string().optional(),
    familyName: z.string().optional(),
  }).optional(),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email format'),
});

const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z.string().min(1, 'New password is required'),
});

export async function signup(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = signupSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    // Check rate limit
    const ip = req.ip || 'unknown';
    const rateLimit = await checkRateLimit('signup', ip);
    if (!rateLimit.allowed) {
      res.setHeader('X-RateLimit-Remaining', rateLimit.remaining);
      res.setHeader('X-RateLimit-Reset', rateLimit.resetAt);
      errorResponse(
        res,
        ErrorCodes.RATE_LIMIT_EXCEEDED.code,
        'Too many signup attempts. Please try again later.',
        ErrorCodes.RATE_LIMIT_EXCEEDED.status
      );
      return;
    }

    const result = await authService.signup(validation.data);
    successResponse(res, result, 201, 'Verification email sent. Please check your inbox.');
  } catch (error) {
    next(error);
  }
}

export async function login(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    // Check rate limit
    const ip = req.ip || 'unknown';
    const rateLimit = await checkRateLimit('login', ip);
    if (!rateLimit.allowed) {
      res.setHeader('X-RateLimit-Remaining', rateLimit.remaining);
      res.setHeader('X-RateLimit-Reset', rateLimit.resetAt);
      errorResponse(
        res,
        ErrorCodes.RATE_LIMIT_EXCEEDED.code,
        'Too many login attempts. Please try again later.',
        ErrorCodes.RATE_LIMIT_EXCEEDED.status
      );
      return;
    }

    const result = await authService.login({
      ...validation.data,
      ipAddress: ip,
      userAgent: req.headers['user-agent'],
    });

    res.setHeader('X-RateLimit-Remaining', rateLimit.remaining);
    successResponse(res, result);
  } catch (error) {
    next(error);
  }
}

export async function refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = refreshSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    const result = await authService.refreshTokens(validation.data.refreshToken);
    successResponse(res, result);
  } catch (error) {
    next(error);
  }
}

export async function logout(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      errorResponse(
        res,
        ErrorCodes.UNAUTHORIZED.code,
        'User not authenticated',
        ErrorCodes.UNAUTHORIZED.status
      );
      return;
    }

    const { refreshToken } = req.body;
    await authService.logout(userId, refreshToken);

    // Blacklist the access token
    if (req.user?.jti && req.user?.exp) {
      const expiresIn = req.user.exp - Math.floor(Date.now() / 1000);
      if (expiresIn > 0) {
        await blacklistToken(req.user.jti, expiresIn);
      }
    }

    successResponse(res, null, 200, 'Logged out successfully');
  } catch (error) {
    next(error);
  }
}

export async function verifyEmail(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = verifyEmailSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    await authService.verifyEmail(validation.data.token);
    successResponse(res, null, 200, 'Email verified successfully');
  } catch (error) {
    next(error);
  }
}

export async function forgotPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = forgotPasswordSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    await authService.requestPasswordReset(validation.data.email);
    
    // Always return success to prevent email enumeration
    successResponse(res, null, 200, 'If the email exists, a reset link has been sent.');
  } catch (error) {
    next(error);
  }
}

export async function resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const validation = resetPasswordSchema.safeParse(req.body);
    if (!validation.success) {
      errorResponse(
        res,
        ErrorCodes.VALIDATION_ERROR.code,
        'Request validation failed',
        ErrorCodes.VALIDATION_ERROR.status,
        validation.error.errors.map((e) => ({ field: e.path.join('.'), message: e.message }))
      );
      return;
    }

    await authService.resetPassword(validation.data.token, validation.data.newPassword);
    successResponse(res, null, 200, 'Password has been reset successfully.');
  } catch (error) {
    next(error);
  }
}

export async function getMe(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.sub;
    if (!userId) {
      errorResponse(
        res,
        ErrorCodes.UNAUTHORIZED.code,
        'User not authenticated',
        ErrorCodes.UNAUTHORIZED.status
      );
      return;
    }

    const user = await authService.getUser(userId);
    successResponse(res, user);
  } catch (error) {
    next(error);
  }
}
