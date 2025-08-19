import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { TwoFactorAuthService } from '../security/two-factor-auth.service';
import { SessionService } from '../security/session.service';

@Injectable()
export class TwoFactorGuard implements CanActivate {
  private readonly logger = new Logger(TwoFactorGuard.name);

  constructor(
    private readonly twoFactorService: TwoFactorAuthService,
    private readonly sessionService: SessionService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const skipTwoFactor = this.reflector.getAllAndOverride<boolean>('skipTwoFactor', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipTwoFactor) {
      return true;
    }

    const gqlContext = GqlExecutionContext.create(context);
    const { req } = gqlContext.getContext();
    const user = req.user;

    if (!user) {
      throw new UnauthorizedException('User not authenticated');
    }

    // Check if 2FA is enabled for user
    const twoFactorEnabled = await this.twoFactorService.isTwoFactorEnabled(user.id);
    if (!twoFactorEnabled) {
      return true; // 2FA not enabled, allow access
    }

    // Check session 2FA verification
    const sessionId = req.sessionId;
    if (!sessionId) {
      throw new UnauthorizedException('Session required for 2FA verification');
    }

    const session = await this.sessionService.getSession(sessionId);
    if (!session || !session.isTwoFactorVerified) {
      throw new UnauthorizedException('Two-factor authentication required');
    }

    return true;
  }
}