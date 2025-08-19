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
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            name: 'default',
            ttl: 60 * 1000, // 1 minute
            limit: 100, // 100 requests per minute
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
       
        ignoreUserAgents: [/googlebot/gi, /bingbot/gi],
      }),
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