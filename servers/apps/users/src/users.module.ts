// Update your users.module.ts
import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import {
  ApolloFederationDriver,
  ApolloFederationDriverConfig,
} from '@nestjs/apollo';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
// Core modules
import { UsersResolver } from './user.resolver';
import { EmailModule } from './email/email.module';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from './users.service';
// Security modules
import { RateLimitingModule } from './security/rate-limiting.module';
import { CsrfModule } from './security/csrf.module';
import { SessionModule } from './security/session.module';
import { AccountLockoutService } from './security/account-lockout.service';
import { TwoFactorAuthService } from './security/two-factor-auth.service';
// Guards
import { AuthGuard } from './guards/auth.guard';
import { CsrfGuard } from './security/guards/csrf.guard';
import { TwoFactorGuard } from './security/guards/two-factor.guard';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: {
        // Add validation for security-related env vars
        CSRF_SECRET: Joi.string().min(32),
        RATE_LIMIT_TTL: Joi.number().default(60),
        RATE_LIMIT_MAX: Joi.number().default(100),
        SESSION_SECRET: Joi.string().min(32),
        TWO_FACTOR_APP_NAME: Joi.string().default('Food Delivery'),
      },
    }),
    GraphQLModule.forRoot<ApolloFederationDriverConfig>({
      driver: ApolloFederationDriver,
      autoSchemaFile: {
        federation: 2,
      },
      context: ({ req, res }) => ({
        req,
        res,
        // Add CSRF token to GraphQL context
        csrfToken: req.headers['x-csrf-token'],
      }),
    }),
    EmailModule,
    RateLimitingModule,
    CsrfModule,
    SessionModule,
  ],
  controllers: [],
  providers: [
    UsersService,
    ConfigService,
    JwtService,
    PrismaService,
    UsersResolver,
    AccountLockoutService,
    TwoFactorAuthService,
    // Apply guards globally
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class UsersModule {}