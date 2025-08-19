import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloFederationDriver, ApolloFederationDriverConfig } from '@nestjs/apollo';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import * as Joi from 'joi';
import { UsersResolver } from './user.resolver';
import { EmailModule } from './email/email.module';
import { PrismaModule } from '../../../prisma/prisma.module';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { RateLimitingModule } from './security/rate-limiting.module';
import { CsrfModule } from './security/csrf.module';
import { SessionModule } from './security/session.module';
import { AccountLockoutService } from './security/account-lockout.service';
import { TwoFactorAuthService } from './security/two-factor-auth.service';
import { AuthGuard } from './guards/auth.guard';
import { SessionService } from './security/session.service';
import configuration, { validateConfig } from './config/configuration';
import { Reflector } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate: validateConfig,
      validationSchema: Joi.object({
        DATABASE_URL: Joi.string().required(),
        ACTIVATION_SECRET: Joi.string().min(32).required(),
        ACCESS_TOKEN_SECRET: Joi.string().min(32).required(),
        REFRESH_TOKEN_SECRET: Joi.string().min(32).required(),
        FORGOT_PASSWORD_SECRET: Joi.string().min(32).required(),
        CLIENT_SIDE_URI: Joi.string().uri().required(),
        SMTP_HOST: Joi.string().required(),
        SMTP_MAIL: Joi.string().email().required(),
        SMTP_PASSWORD: Joi.string().required(),
        PORT: Joi.number().port().default(4001),
        NODE_ENV: Joi.string().default('development'),
        CSRF_SECRET: Joi.string().min(32).optional(),
        RATE_LIMIT_TTL: Joi.number().default(60),
        RATE_LIMIT_MAX: Joi.number().default(100),
        SESSION_SECRET: Joi.string().min(32).optional(),
        TWO_FACTOR_APP_NAME: Joi.string().default('Food Delivery'),
      }),
    }),
    GraphQLModule.forRoot<ApolloFederationDriverConfig>({
      driver: ApolloFederationDriver,
      autoSchemaFile: {
        federation: 2,
      },
      context: ({ req, res }) => ({
        req,
        res,
        csrfToken: req.headers['x-csrf-token'],
      }),
      introspection: process.env.NODE_ENV !== 'production',
      playground: process.env.NODE_ENV !== 'production',
    }),
    PrismaModule,
    EmailModule,
    // Only add rate limiting module if not in test environment
    ...(process.env.NODE_ENV !== 'test' ? [RateLimitingModule] : []),
    CsrfModule,
    SessionModule,
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('ACCESS_TOKEN_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [UsersController],
  providers: [
    UsersService,
    ConfigService,
    JwtService,
    UsersResolver,
    AccountLockoutService,
    TwoFactorAuthService,
    SessionService,
    AuthGuard,
    Reflector,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class UsersModule {}