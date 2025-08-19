import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../../../prisma/prisma.service';
import { SessionService } from '../security/session.service';
import { TwoFactorAuthService } from '../security/two-factor-auth.service';
import { AccountLockoutService } from '../security/account-lockout.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly reflector: Reflector,
    private readonly sessionService: SessionService,
    private readonly twoFactorService: TwoFactorAuthService,
    private readonly lockoutService: AccountLockoutService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

      if (isPublic) {
        return true; // Skip authentication for public endpoints
      }

      const gqlContext = GqlExecutionContext.create(context);
      const { req } = gqlContext.getContext();

      const accessToken = req.headers.accesstoken as string;
      const refreshToken = req.headers.refreshtoken as string;
      const sessionId = req.headers.sessionid as string;

      if (!accessToken || !refreshToken) {
        throw new UnauthorizedException('Authentication tokens are required');
      }

      // Validate session if provided
      if (sessionId) {
        const session = await this.sessionService.getSession(sessionId);
        if (!session || !session.isActive) {
          throw new UnauthorizedException('Invalid or expired session');
        }
        await this.sessionService.updateSessionActivity(sessionId);
        req.sessionId = sessionId;
        req.session = session;
      }

      // Validate and potentially refresh access token
      try {
        const decoded = this.jwtService.verify(accessToken, {
          secret: this.config.get<string>('ACCESS_TOKEN_SECRET'),
        });
        await this.attachUserToRequest(req, decoded.id);
        await this.checkTwoFactorRequirement(context, req);
      } catch (jwtError) {
        this.logger.warn('Access token verification failed', jwtError.message);
        await this.updateAccessToken(req);
        await this.checkTwoFactorRequirement(context, req);
      }

      return true;
    } catch (error) {
      this.logger.error('Authentication guard error', error.stack);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Authentication failed');
    }
  }

  private async checkTwoFactorRequirement(context: ExecutionContext, req: any): Promise<void> {
    const skipTwoFactor = this.reflector.getAllAndOverride<boolean>('skipTwoFactor', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (skipTwoFactor) {
      return;
    }
    const user = req.user;
    if (!user) {
      return;
    }
    const twoFactorEnabled = await this.twoFactorService.isTwoFactorEnabled(user.id);
    if (!twoFactorEnabled) {
      return;
    }
    const session = req.session;
    if (!session || !session.isTwoFactorVerified) {
      throw new UnauthorizedException('Two-factor authentication required');
    }
  }

  private async updateAccessToken(req: any): Promise<void> {
    try {
      const refreshTokenData = req.headers.refreshtoken as string;
      if (!refreshTokenData) {
        throw new UnauthorizedException('Refresh token is required');
      }
      const decoded = this.jwtService.verify(refreshTokenData, {
        secret: this.config.get<string>('REFRESH_TOKEN_SECRET'),
      });
      if (!decoded?.id) {
        throw new UnauthorizedException('Invalid refresh token structure');
      }
      const expirationTime = decoded.exp * 1000;
      if (expirationTime < Date.now()) {
        throw new UnauthorizedException('Refresh token expired. Please login again.');
      }
      const lockoutStatus = await this.lockoutService.checkAccountLockout(decoded.id);
      if (lockoutStatus.isLocked) {
        throw new UnauthorizedException(
          `Account is locked until ${lockoutStatus.unlockTime?.toISOString()}`,
        );
      }
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.id },
        include: { avatar: true },
      });
      if (!user) {
        throw new UnauthorizedException('User not found. Please login again.');
      }
      const accessTokenSecret = this.config.get<string>('ACCESS_TOKEN_SECRET');
      const refreshTokenSecret = this.config.get<string>('REFRESH_TOKEN_SECRET');
      if (!accessTokenSecret || !refreshTokenSecret) {
        throw new InternalServerErrorException('Server configuration error');
      }
      const newAccessToken = this.jwtService.sign(
        { id: user.id },
        { secret: accessTokenSecret, expiresIn: '15m' },
      );
      const newRefreshToken = this.jwtService.sign(
        { id: user.id },
        { secret: refreshTokenSecret, expiresIn: '7d' },
      );
      req.accesstoken = newAccessToken;
      req.refreshtoken = newRefreshToken;
      req.user = user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Token refresh failed. Please login again.');
    }
  }

  private async attachUserToRequest(req: any, userId: string): Promise<void> {
    try {
      const lockoutStatus = await this.lockoutService.checkAccountLockout(userId);
      if (lockoutStatus.isLocked) {
        throw new UnauthorizedException(
          `Account is locked until ${lockoutStatus.unlockTime?.toISOString()}`,
        );
      }
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { avatar: true },
      });
      if (!user) {
        throw new UnauthorizedException('User not found. Please login again.');
      }
      req.user = user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('User verification failed');
    }
  }
}