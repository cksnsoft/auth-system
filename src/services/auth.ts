import { prisma } from '../config/database.js';
import { hashPassword, verifyPassword, validatePassword } from '../utils/password.js';
import { generateAccessToken, generateIdToken, getTokenExpirationSeconds } from '../utils/jwt.js';
import { generateRefreshToken, hashRefreshToken, generateEmailToken } from '../utils/tokens.js';
import { jwtConfig } from '../config/index.js';

interface SignupInput {
  email: string;
  password: string;
  profile?: {
    givenName?: string;
    familyName?: string;
  };
}

interface LoginInput {
  email: string;
  password: string;
  ipAddress?: string;
  userAgent?: string;
}

interface TokenResponse {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

const LOCK_THRESHOLD = 5;
const LOCK_DURATION_MINUTES = 30;
const REFRESH_TOKEN_DAYS = 30;

export async function signup(input: SignupInput) {
  const { email, password, profile } = input;

  // Validate password
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    throw {
      code: 'VALIDATION_ERROR',
      message: 'Password does not meet requirements',
      details: passwordValidation.errors,
    };
  }

  // Check if email already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (existingUser) {
    throw {
      code: 'EMAIL_ALREADY_EXISTS',
      message: 'A user with this email already exists',
    };
  }

  // Hash password and create user
  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash,
      status: 'UNVERIFIED',
      profile: profile ? {
        create: {
          givenName: profile.givenName,
          familyName: profile.familyName,
        },
      } : undefined,
    },
    include: {
      profile: true,
    },
  });

  // Generate email verification token
  const emailToken = generateEmailToken();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  await prisma.emailVerificationToken.create({
    data: {
      userId: user.id,
      token: emailToken,
      expiresAt,
    },
  });

  // TODO: Send verification email

  return {
    id: user.id,
    email: user.email,
    status: user.status,
    createdAt: user.createdAt,
    verificationToken: emailToken, // In production, don't return this - send via email
  };
}

export async function login(input: LoginInput): Promise<TokenResponse> {
  const { email, password, ipAddress, userAgent } = input;

  // Find user
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
    include: { profile: true },
  });

  if (!user) {
    throw {
      code: 'INVALID_CREDENTIALS',
      message: 'The email or password is incorrect',
    };
  }

  // Check if account is locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw {
      code: 'ACCOUNT_LOCKED',
      message: `Account is locked. Try again after ${user.lockedUntil.toISOString()}`,
    };
  }

  // Verify password
  const isValid = await verifyPassword(password, user.passwordHash);

  if (!isValid) {
    // Increment failed attempts
    const failedAttempts = user.failedLoginAttempts + 1;
    const updateData: { failedLoginAttempts: number; lockedUntil?: Date } = {
      failedLoginAttempts: failedAttempts,
    };

    if (failedAttempts >= LOCK_THRESHOLD) {
      updateData.lockedUntil = new Date(Date.now() + LOCK_DURATION_MINUTES * 60 * 1000);
    }

    await prisma.user.update({
      where: { id: user.id },
      data: updateData,
    });

    throw {
      code: 'INVALID_CREDENTIALS',
      message: 'The email or password is incorrect',
    };
  }

  // Check user status
  if (user.status === 'DISABLED') {
    throw {
      code: 'ACCOUNT_DISABLED',
      message: 'This account has been disabled',
    };
  }

  if (user.status === 'UNVERIFIED') {
    throw {
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Please verify your email before logging in',
    };
  }

  // Reset failed attempts and update last login
  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: new Date(),
    },
  });

  // Generate tokens
  const accessToken = generateAccessToken(user);
  const idToken = generateIdToken(user);
  const refreshToken = generateRefreshToken();

  // Save refresh token
  const refreshTokenExpiresAt = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: hashRefreshToken(refreshToken),
      expiresAt: refreshTokenExpiresAt,
      ipAddress,
      userAgent,
    },
  });

  // Log audit event
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      eventType: 'LOGIN_SUCCESS',
      eventData: { method: 'password' },
      ipAddress,
      userAgent,
    },
  });

  return {
    accessToken,
    idToken,
    refreshToken,
    expiresIn: getTokenExpirationSeconds(jwtConfig.accessTokenExpiresIn),
    tokenType: 'Bearer',
  };
}

export async function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  const tokenHash = hashRefreshToken(refreshToken);

  // Find token
  const storedToken = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: {
      user: {
        include: { profile: true },
      },
    },
  });

  if (!storedToken) {
    throw {
      code: 'INVALID_TOKEN',
      message: 'Invalid refresh token',
    };
  }

  // Check if revoked
  if (storedToken.revokedAt) {
    // Token reuse detected - revoke all tokens for this user
    await prisma.refreshToken.updateMany({
      where: { userId: storedToken.userId },
      data: { revokedAt: new Date() },
    });

    throw {
      code: 'INVALID_TOKEN',
      message: 'Token has been revoked. Please log in again.',
    };
  }

  // Check if expired
  if (storedToken.expiresAt < new Date()) {
    throw {
      code: 'TOKEN_EXPIRED',
      message: 'Refresh token has expired. Please log in again.',
    };
  }

  // Check user status
  if (storedToken.user.status !== 'ACTIVE') {
    throw {
      code: 'ACCOUNT_DISABLED',
      message: 'This account is not active',
    };
  }

  // Revoke old token
  await prisma.refreshToken.update({
    where: { id: storedToken.id },
    data: { revokedAt: new Date() },
  });

  // Generate new tokens
  const accessToken = generateAccessToken(storedToken.user);
  const idToken = generateIdToken(storedToken.user);
  const newRefreshToken = generateRefreshToken();

  // Save new refresh token
  const refreshTokenExpiresAt = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);

  await prisma.refreshToken.create({
    data: {
      userId: storedToken.userId,
      tokenHash: hashRefreshToken(newRefreshToken),
      expiresAt: refreshTokenExpiresAt,
      ipAddress: storedToken.ipAddress,
      userAgent: storedToken.userAgent,
    },
  });

  return {
    accessToken,
    idToken,
    refreshToken: newRefreshToken,
    expiresIn: getTokenExpirationSeconds(jwtConfig.accessTokenExpiresIn),
    tokenType: 'Bearer',
  };
}

export async function logout(userId: string, refreshToken?: string): Promise<void> {
  if (refreshToken) {
    const tokenHash = hashRefreshToken(refreshToken);
    await prisma.refreshToken.updateMany({
      where: { tokenHash, userId },
      data: { revokedAt: new Date() },
    });
  } else {
    // Revoke all refresh tokens for this user
    await prisma.refreshToken.updateMany({
      where: { userId },
      data: { revokedAt: new Date() },
    });
  }
}

export async function verifyEmail(token: string): Promise<void> {
  const verificationToken = await prisma.emailVerificationToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!verificationToken) {
    throw {
      code: 'INVALID_TOKEN',
      message: 'Invalid verification token',
    };
  }

  if (verificationToken.usedAt) {
    throw {
      code: 'INVALID_TOKEN',
      message: 'This token has already been used',
    };
  }

  if (verificationToken.expiresAt < new Date()) {
    throw {
      code: 'TOKEN_EXPIRED',
      message: 'Verification token has expired',
    };
  }

  // Update user and token
  await prisma.$transaction([
    prisma.user.update({
      where: { id: verificationToken.userId },
      data: {
        emailVerified: true,
        status: 'ACTIVE',
      },
    }),
    prisma.emailVerificationToken.update({
      where: { id: verificationToken.id },
      data: { usedAt: new Date() },
    }),
  ]);
}

export async function requestPasswordReset(email: string): Promise<string | null> {
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (!user) {
    // Don't reveal whether email exists
    return null;
  }

  // Generate reset token
  const resetToken = generateEmailToken();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      token: resetToken,
      expiresAt,
    },
  });

  // TODO: Send reset email

  return resetToken; // In production, don't return this - send via email
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  // Validate new password
  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.valid) {
    throw {
      code: 'VALIDATION_ERROR',
      message: 'Password does not meet requirements',
      details: passwordValidation.errors,
    };
  }

  const resetToken = await prisma.passwordResetToken.findUnique({
    where: { token },
  });

  if (!resetToken) {
    throw {
      code: 'INVALID_TOKEN',
      message: 'Invalid reset token',
    };
  }

  if (resetToken.usedAt) {
    throw {
      code: 'INVALID_TOKEN',
      message: 'This token has already been used',
    };
  }

  if (resetToken.expiresAt < new Date()) {
    throw {
      code: 'TOKEN_EXPIRED',
      message: 'Reset token has expired',
    };
  }

  // Update password and mark token as used
  const passwordHash = await hashPassword(newPassword);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: resetToken.userId },
      data: {
        passwordHash,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    }),
    prisma.passwordResetToken.update({
      where: { id: resetToken.id },
      data: { usedAt: new Date() },
    }),
    // Revoke all refresh tokens
    prisma.refreshToken.updateMany({
      where: { userId: resetToken.userId },
      data: { revokedAt: new Date() },
    }),
  ]);
}

export async function getUser(userId: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { profile: true },
  });

  if (!user) {
    throw {
      code: 'USER_NOT_FOUND',
      message: 'User not found',
    };
  }

  return {
    id: user.id,
    email: user.email,
    emailVerified: user.emailVerified,
    status: user.status,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    profile: user.profile ? {
      givenName: user.profile.givenName,
      familyName: user.profile.familyName,
      nickname: user.profile.nickname,
      phoneNumber: user.profile.phoneNumber,
      pictureUrl: user.profile.pictureUrl,
      locale: user.profile.locale,
      timezone: user.profile.timezone,
    } : null,
  };
}
