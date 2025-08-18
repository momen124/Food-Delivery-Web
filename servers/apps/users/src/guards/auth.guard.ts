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
import { PrismaService } from "../../prisma/prisma.service";

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const gqlContext = GqlExecutionContext.create(context);
      const { req } = gqlContext.getContext();

      const accessToken = req.headers.accesstoken as string;
      const refreshToken = req.headers.refreshtoken as string;

      // Check if tokens are present
      if (!accessToken || !refreshToken) {
        this.logger.warn('Missing authentication tokens');
        throw new UnauthorizedException('Authentication tokens are required. Please login to access this resource!');
      }

      // Validate and potentially refresh access token
      if (accessToken) {
        try {
          const decoded = this.jwtService.decode(accessToken);

          if (!decoded) {
            this.logger.warn('Invalid access token format');
            throw new UnauthorizedException('Invalid access token format');
          }

          const expirationTime = decoded?.exp;

          if (!expirationTime) {
            this.logger.warn('Access token missing expiration');
            throw new UnauthorizedException('Invalid token structure');
          }

          // If token is expired, try to refresh it
          if (expirationTime * 1000 < Date.now()) {
            this.logger.log('Access token expired, attempting to refresh');
            await this.updateAccessToken(req);
          } else {
            // Token is valid, verify user exists and attach to request
            await this.attachUserToRequest(req, decoded.id);
          }
        } catch (jwtError) {
          this.logger.warn('Access token verification failed', jwtError.message);
          throw new UnauthorizedException('Invalid access token');
        }
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

  private async updateAccessToken(req: any): Promise<void> {
    try {
      const refreshTokenData = req.headers.refreshtoken as string;

      if (!refreshTokenData) {
        throw new UnauthorizedException('Refresh token is required');
      }

      // Verify refresh token
      let decoded: any;
      try {
        decoded = this.jwtService.verify(refreshTokenData, {
          secret: this.config.get<string>('REFRESH_TOKEN_SECRET'),
        });
      } catch (jwtError) {
        this.logger.warn('Invalid refresh token', jwtError.message);
        throw new UnauthorizedException('Invalid or expired refresh token. Please login again.');
      }

      if (!decoded?.id) {
        throw new UnauthorizedException('Invalid refresh token structure');
      }

      const expirationTime = decoded.exp * 1000;

      if (expirationTime < Date.now()) {
        this.logger.warn('Refresh token expired');
        throw new UnauthorizedException('Refresh token expired. Please login again.');
      }

      // Find user in database
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.id },
        include: { avatar: true }
      });

      if (!user) {
        this.logger.warn(`User not found during token refresh: ${decoded.id}`);
        throw new UnauthorizedException('User not found. Please login again.');
      }

      // Generate new tokens
      const accessTokenSecret = this.config.get<string>('ACCESS_TOKEN_SECRET');
      const refreshTokenSecret = this.config.get<string>('REFRESH_TOKEN_SECRET');

      if (!accessTokenSecret || !refreshTokenSecret) {
        this.logger.error('Missing token secrets in configuration');
        throw new InternalServerErrorException('Server configuration error');
      }

      const newAccessToken = this.jwtService.sign(
        { id: user.id },
        {
          secret: accessTokenSecret,
          expiresIn: '15m', // Increased from 5m for better UX
        },
      );

      const newRefreshToken = this.jwtService.sign(
        { id: user.id },
        {
          secret: refreshTokenSecret,
          expiresIn: '7d',
        },
      );

      // Attach new tokens and user to request
      req.accesstoken = newAccessToken;
      req.refreshtoken = newRefreshToken;
      req.user = user;

      this.logger.log(`Tokens refreshed successfully for user: ${user.id}`);

    } catch (error) {
      this.logger.error('Token refresh failed', error.stack);
      
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      throw new UnauthorizedException('Token refresh failed. Please login again.');
    }
  }

  private async attachUserToRequest(req: any, userId: string): Promise<void> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { avatar: true }
      });

      if (!user) {
        this.logger.warn(`User not found during authentication: ${userId}`);
        throw new UnauthorizedException('User not found. Please login again.');
      }

      req.user = user;

    } catch (error) {
      this.logger.error('Failed to attach user to request', error.stack);
      
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      throw new UnauthorizedException('User verification failed');
    }
  }

  // Utility method to validate required configuration
  private validateConfiguration(): void {
    const requiredSecrets = ['ACCESS_TOKEN_SECRET', 'REFRESH_TOKEN_SECRET'];
    
    for (const secret of requiredSecrets) {
      if (!this.config.get<string>(secret)) {
        this.logger.error(`Missing required configuration: ${secret}`);
        throw new InternalServerErrorException('Server configuration error');
      }
    }
  }

  // Initialize guard with configuration validation
  onModuleInit() {
    try {
      this.validateConfiguration();
      this.logger.log('AuthGuard initialized successfully');
    } catch (error) {
      this.logger.error('AuthGuard initialization failed', error.stack);
      throw error;
    }
  }
}