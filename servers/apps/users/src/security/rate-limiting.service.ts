import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'prisma/Prisma.service';
export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}
@Injectable()
export class RateLimitingService {
  private readonly logger = new Logger(RateLimitingService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}
  async checkRateLimit(
    identifier: string,
    config: RateLimitConfig,
  ): Promise<{ allowed: boolean; remainingRequests: number; resetTime: Date }> {
    const windowStart = new Date(Date.now() - config.windowMs);
   
    try {
      // Clean old entries
      await this.prisma.rateLimitEntry.deleteMany({
        where: {
          identifier,
          createdAt: { lt: windowStart },
        },
      });
      // Count current requests
      const currentRequests = await this.prisma.rateLimitEntry.count({
        where: {
          identifier,
          createdAt: { gte: windowStart },
        },
      });
      const allowed = currentRequests < config.maxRequests;
      const remainingRequests = Math.max(0, config.maxRequests - currentRequests);
      const resetTime = new Date(Date.now() + config.windowMs);
      if (allowed) {
        // Record this request
        await this.prisma.rateLimitEntry.create({
          data: {
            identifier,
            createdAt: new Date(),
          },
        });
      }
      return { allowed, remainingRequests, resetTime };
    } catch (error) {
      this.logger.error(`Rate limiting check failed for ${identifier}`, error.stack);
      // Allow request on error to avoid blocking legitimate users
      return { allowed: true, remainingRequests: config.maxRequests, resetTime: new Date() };
    }
  }
  async isRateLimited(identifier: string, windowMs: number, maxRequests: number): Promise<boolean> {
    const result = await this.checkRateLimit(identifier, { windowMs, maxRequests });
    return !result.allowed;
  }
}