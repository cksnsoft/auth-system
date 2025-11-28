import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import pinoHttp from 'pino-http';

import { config } from './config/index.js';
import { logger } from './config/logger.js';
import { redis } from './config/redis.js';
import { prisma } from './config/database.js';
import { authMiddleware } from './middlewares/auth.js';
import { errorHandler } from './middlewares/errorHandler.js';
import * as authController from './controllers/auth.js';

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: config.NODE_ENV === 'production' 
    ? ['https://your-frontend.com'] 
    : ['http://localhost:3001'],
  credentials: true,
}));
app.use(express.json());
app.use(pinoHttp({ logger }));

// Health check
app.get('/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await redis.ping();
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', error: String(error) });
  }
});

// Auth routes (public)
app.post('/auth/signup', authController.signup);
app.post('/auth/login', authController.login);
app.post('/auth/refresh', authController.refresh);
app.post('/auth/verify-email', authController.verifyEmail);
app.post('/auth/forgot-password', authController.forgotPassword);
app.post('/auth/reset-password', authController.resetPassword);

// Auth routes (protected)
app.post('/auth/logout', authMiddleware, authController.logout);

// User routes (protected)
app.get('/users/me', authMiddleware, authController.getMe);

// Error handler
app.use(errorHandler);

// Start server
async function start() {
  try {
    // Connect to Redis
    await redis.connect();
    logger.info('Redis connected');

    // Test database connection
    await prisma.$connect();
    logger.info('Database connected');

    // Start HTTP server
    app.listen(config.PORT, () => {
      logger.info(`Server running on port ${config.PORT}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down...');
  await prisma.$disconnect();
  await redis.quit();
  process.exit(0);
});

start();
