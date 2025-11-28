import { Response } from 'express';

interface SuccessResponse<T> {
  success: true;
  data: T;
  message?: string;
}

interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export function successResponse<T>(res: Response, data: T, statusCode = 200, message?: string): void {
  const response: SuccessResponse<T> = {
    success: true,
    data,
    ...(message && { message }),
  };
  res.status(statusCode).json(response);
}

export function errorResponse(
  res: Response,
  code: string,
  message: string,
  statusCode = 400,
  details?: unknown
): void {
  const response: ErrorResponse = {
    success: false,
    error: {
      code,
      message,
      ...(details && { details }),
    },
  };
  res.status(statusCode).json(response);
}

export const ErrorCodes = {
  VALIDATION_ERROR: { code: 'VALIDATION_ERROR', status: 400 },
  INVALID_TOKEN: { code: 'INVALID_TOKEN', status: 400 },
  INVALID_CREDENTIALS: { code: 'INVALID_CREDENTIALS', status: 401 },
  TOKEN_EXPIRED: { code: 'TOKEN_EXPIRED', status: 401 },
  UNAUTHORIZED: { code: 'UNAUTHORIZED', status: 401 },
  EMAIL_NOT_VERIFIED: { code: 'EMAIL_NOT_VERIFIED', status: 403 },
  ACCOUNT_DISABLED: { code: 'ACCOUNT_DISABLED', status: 403 },
  ACCOUNT_LOCKED: { code: 'ACCOUNT_LOCKED', status: 403 },
  USER_NOT_FOUND: { code: 'USER_NOT_FOUND', status: 404 },
  EMAIL_ALREADY_EXISTS: { code: 'EMAIL_ALREADY_EXISTS', status: 409 },
  RATE_LIMIT_EXCEEDED: { code: 'RATE_LIMIT_EXCEEDED', status: 429 },
  INTERNAL_ERROR: { code: 'INTERNAL_ERROR', status: 500 },
} as const;
