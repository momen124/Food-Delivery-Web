import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RateLimitingService } from './rate-limiting.service';
import { CustomThrottlerGuard } from '../guards/custom-throttler.guard';

@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const isTestEnvironment = config.get('NODE_ENV') === 'test';
        
        return {
          throttlers: isTestEnvironment 
            ? [
                {
                  name: 'default',
                  ttl: 60 * 1000, // 1 minute
                  limit: 1000, // Much higher limits for tests
                },
                {
                  name: 'auth',
                  ttl: 15 * 60 * 1000, // 15 minutes
                  limit: 50, // Higher limits for auth in tests
                },
                {
                  name: 'registration',
                  ttl: 60 * 60 * 1000, // 1 hour
                  limit: 30, // Higher limits for registration in tests
                },
              ]
            : [
                {
                  name: 'default',
                  ttl: 60 * 1000, // 1 minute
                  limit: 100, // Normal production limits
                },
                {
                  name: 'auth',
                  ttl: 15 * 60 * 1000, // 15 minutes
                  limit: 5, // 5 login attempts per 15 minutes
                },
                {
                  name: 'registration',
                  ttl: 60 * 60 * 1000, // 1 hour
                  limit: 3, // 3 registration attempts per hour
                },
              ],
          ignoreUserAgents: isTestEnvironment 
            ? [/jest/gi, /supertest/gi, /node/gi, /googlebot/gi, /bingbot/gi]
            : [/googlebot/gi, /bingbot/gi],
        };
      },
    }),
  ],
  providers: [
    RateLimitingService,
    {
      provide: APP_GUARD,
      useClass: CustomThrottlerGuard,
    },
  ],
  exports: [RateLimitingService],
})
export class RateLimitingModule {}