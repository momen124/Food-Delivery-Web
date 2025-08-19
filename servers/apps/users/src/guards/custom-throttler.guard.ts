import { Injectable, ExecutionContext, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerException, ThrottlerLimitDetail, ThrottlerModuleOptions, ThrottlerStorage } from '@nestjs/throttler';
import { GqlExecutionContext } from '@nestjs/graphql';
import { THROTTLER_OPTIONS } from '@nestjs/throttler/dist/throttler.constants';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  constructor(
    @Inject(THROTTLER_OPTIONS) options: ThrottlerModuleOptions,
    @Inject('THROTTLER_STORAGE') storageService: ThrottlerStorage,
    protected readonly reflector: Reflector,
    private readonly configService: ConfigService,
  ) {
    super(options, storageService, reflector);
  }

  protected async getTracker(req: Record<string, any>): Promise<string> {
    // Skip rate limiting in test environment
    if (this.configService.get('NODE_ENV') === 'test') {
      return `test:${Date.now()}-${Math.random()}`;
    }

    // Use user ID if authenticated, otherwise fall back to IP
    const userId = req?.user?.id;
    if (userId) {
      return `user:${userId}`;
    }

    // Get real IP address considering proxies
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded
      ? (Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0]).trim()
      : req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip || 'unknown';

    return `ip:${ip}`;
  }

  protected getRequestResponse(context: ExecutionContext) {
    const gqlCtx = GqlExecutionContext.create(context);
    const ctx = gqlCtx.getContext();
    return { req: ctx.req, res: ctx.res };
  }

  protected async throwThrottlingException(
    context: ExecutionContext,
    throttlerLimitDetail?: ThrottlerLimitDetail
  ): Promise<void> {
    throw new ThrottlerException('Too many requests, please try again later.');
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Skip throttling in test environment
    if (this.configService.get('NODE_ENV') === 'test') {
      return true;
    }

    return super.canActivate(context);
  }
}