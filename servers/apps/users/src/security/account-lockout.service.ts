// Fixed imports for account-lockout.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../../../prisma/prisma.service';

export interface LockoutConfig {
  maxAttempts: number;
  lockoutDuration: number; // in milliseconds
  decayDuration?: number; // time after which attempts reset
}

@Injectable()
export class AccountLockoutService {
  private readonly logger = new Logger(AccountLockoutService.name);
 
  private readonly defaultConfig: LockoutConfig = {
    maxAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    decayDuration: 60 * 60 * 1000, // 1 hour
  };

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  // ... rest of the service implementation remains the same
  async recordFailedAttempt(identifier: string, config?: Partial<LockoutConfig>): Promise<void> {
    const lockoutConfig = { ...this.defaultConfig, ...config };
   
    try {
      const now = new Date();
      const decayTime = new Date(now.getTime() - lockoutConfig.decayDuration);

      // Clean old attempts
      await this.prisma.loginAttempt.deleteMany({
        where: {
          identifier,
          createdAt: { lt: decayTime },
        },
      });

      // Record new failed attempt
      await this.prisma.loginAttempt.create({
        data: {
          identifier,
          successful: false,
          createdAt: now,
        },
      });

      // Check if account should be locked
      const recentFailures = await this.prisma.loginAttempt.count({
        where: {
          identifier,
          successful: false,
          createdAt: { gte: decayTime },
        },
      });

      if (recentFailures >= lockoutConfig.maxAttempts) {
        await this.lockAccount(identifier, lockoutConfig.lockoutDuration);
        this.logger.warn(`Account locked due to ${recentFailures} failed attempts: ${identifier}`);
      }
    } catch (error) {
      this.logger.error(`Failed to record login attempt for ${identifier}`, error.stack);
    }
  }

  async recordSuccessfulAttempt(identifier: string): Promise<void> {
    try {
      const now = new Date();
     
      // Record successful attempt
      await this.prisma.loginAttempt.create({
        data: {
          identifier,
          successful: true,
          createdAt: now,
        },
      });

      // Clear any existing lockout
      await this.prisma.accountLockout.deleteMany({
        where: { identifier },
      });

      // Clean old failed attempts
      await this.prisma.loginAttempt.deleteMany({
        where: {
          identifier,
          successful: false,
        },
      });
    } catch (error) {
      this.logger.error(`Failed to record successful attempt for ${identifier}`, error.stack);
    }
  }

  async checkAccountLockout(identifier: string): Promise<{ isLocked: boolean; unlockTime?: Date }> {
    try {
      const lockout = await this.prisma.accountLockout.findFirst({
        where: { identifier },
        orderBy: { createdAt: 'desc' },
      });

      if (!lockout) {
        return { isLocked: false };
      }

      const unlockTime = new Date(lockout.createdAt.getTime() + lockout.duration);
      const now = new Date();

      if (now >= unlockTime) {
        // Lockout expired, remove it
        await this.prisma.accountLockout.delete({
          where: { id: lockout.id },
        });
        return { isLocked: false };
      }

      return { isLocked: true, unlockTime };
    } catch (error) {
      this.logger.error(`Failed to check lockout for ${identifier}`, error.stack);
      return { isLocked: false };
    }
  }

  private async lockAccount(identifier: string, duration: number): Promise<void> {
    try {
      // Remove existing lockouts
      await this.prisma.accountLockout.deleteMany({
        where: { identifier },
      });

      // Create new lockout
      await this.prisma.accountLockout.create({
        data: {
          identifier,
          duration,
          createdAt: new Date(),
        },
      });
    } catch (error) {
      this.logger.error(`Failed to lock account ${identifier}`, error.stack);
    }
  }

  async getFailedAttemptCount(identifier: string, windowMs: number = 60 * 60 * 1000): Promise<number> {
    try {
      const windowStart = new Date(Date.now() - windowMs);
      return await this.prisma.loginAttempt.count({
        where: {
          identifier,
          successful: false,
          createdAt: { gte: windowStart },
        },
      });
    } catch (error) {
      this.logger.error(`Failed to get attempt count for ${identifier}`, error.stack);
      return 0;
    }
  }
}