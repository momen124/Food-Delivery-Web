import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException, ThrottlerLimitDetail } from '@nestjs/throttler';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, any>): Promise<string> {
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
}