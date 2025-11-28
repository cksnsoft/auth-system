import { Request, Response, NextFunction } from 'express';
import { errorResponse, ErrorCodes } from '../utils/response.js';
import { logger } from '../config/logger.js';

interface AppError {
  code: string;
  message: string;
  details?: unknown;
}

export function errorHandler(
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  logger.error({
    err,
    method: req.method,
    url: req.url,
    ip: req.ip,
  });

  // Handle known application errors
  if ('code' in err && typeof err.code === 'string') {
    const errorDef = Object.values(ErrorCodes).find((e) => e.code === err.code);
    const status = errorDef?.status || 400;
    errorResponse(res, err.code, err.message, status, (err as AppError).details);
    return;
  }

  // Handle unknown errors
  errorResponse(
    res,
    ErrorCodes.INTERNAL_ERROR.code,
    'An unexpected error occurred',
    ErrorCodes.INTERNAL_ERROR.status
  );
}
