import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import * as crypto from 'crypto';

export interface CreateSessionData {
  userId: string;
  userAgent: string;
  ipAddress: string;
}

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async createSession(data: CreateSessionData): Promise<string> {
    try {
      const sessionId = this.generateSessionId();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      await this.prisma.userSession.create({
        data: {
          id: sessionId,
          userId: data.userId,
          userAgent: data.userAgent,
          ipAddress: data.ipAddress,
          isActive: true,
          lastActivity: new Date(),
          expiresAt,
          isTwoFactorVerified: false,
          createdAt: new Date(),
        },
      });

      this.logger.log(`Session created for user: ${data.userId}`);
      return sessionId;
    } catch (error) {
      this.logger.error(`Failed to create session for user ${data.userId}`, error.stack);
      throw error;
    }
  }

  async getSession(sessionId: string) {
    try {
      const session = await this.prisma.userSession.findUnique({
        where: { id: sessionId },
        include: { user: true },
      });

      if (!session) {
        return null;
      }

      // Check if session is expired
      if (session.expiresAt < new Date()) {
        await this.invalidateSession(sessionId);
        return null;
      }

      return session;
    } catch (error) {
      this.logger.error(`Failed to get session ${sessionId}`, error.stack);
      return null;
    }
  }

  async updateSessionActivity(sessionId: string): Promise<void> {
    try {
      await this.prisma.userSession.update({
        where: { id: sessionId },
        data: { lastActivity: new Date() },
      });
    } catch (error) {
      this.logger.error(`Failed to update session activity ${sessionId}`, error.stack);
    }
  }

  async markTwoFactorVerified(sessionId: string): Promise<void> {
    try {
      await this.prisma.userSession.update({
        where: { id: sessionId },
        data: {
          isTwoFactorVerified: true,
          twoFactorVerifiedAt: new Date(),
        },
      });

      this.logger.log(`2FA verified for session: ${sessionId}`);
    } catch (error) {
      this.logger.error(`Failed to mark 2FA verified for session ${sessionId}`, error.stack);
      throw error;
    }
  }

  async invalidateSession(sessionId: string): Promise<void> {
    try {
      await this.prisma.userSession.update({
        where: { id: sessionId },
        data: {
          isActive: false,
          invalidatedAt: new Date(),
        },
      });

      this.logger.log(`Session invalidated: ${sessionId}`);
    } catch (error) {
      this.logger.error(`Failed to invalidate session ${sessionId}`, error.stack);
    }
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    try {
      await this.prisma.userSession.updateMany({
        where: { userId, isActive: true },
        data: {
          isActive: false,
          invalidatedAt: new Date(),
        },
      });

      this.logger.log(`All sessions invalidated for user: ${userId}`);
    } catch (error) {
      this.logger.error(`Failed to invalidate all sessions for user ${userId}`, error.stack);
    }
  }

  async cleanupExpiredSessions(): Promise<void> {
    try {
      const result = await this.prisma.userSession.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { 
              isActive: false,
              invalidatedAt: { lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // 24 hours ago
            }
          ]
        },
      });

      this.logger.log(`Cleaned up ${result.count} expired sessions`);
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions', error.stack);
    }
  }

  private generateSessionId(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}