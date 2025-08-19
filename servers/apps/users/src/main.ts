import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ValidationPipe, Logger } from '@nestjs/common';
import { join } from 'path';
import { UsersModule } from './users.module';
import { GlobalExceptionFilter } from './filters/global-exception.filter';
import { LoggingInterceptor } from './interceptors/logging.interceptor';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  try {
    logger.log('Starting Food Delivery Users Service...');

    const app = await NestFactory.create<NestExpressApplication>(UsersModule, {
      logger: ['log', 'error', 'warn', 'debug', 'verbose'],
    });

    const configService = app.get(ConfigService);

    // Security middleware
    app.use(helmet({
      contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    }));

    // Rate limiting
    app.use('/graphql', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // Limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
    }));

    // Stricter rate limiting for auth endpoints
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // Only 5 attempts per 15 minutes for auth operations
      message: 'Too many authentication attempts, please try again later.',
      skip: (req) => {
        // Only apply to auth mutations
        const body = req.body;
        const isAuthMutation = body?.query?.includes('register') || 
                              body?.query?.includes('login') || 
                              body?.query?.includes('forgotPassword');
        return !isAuthMutation;
      }
    });

    app.use('/graphql', authLimiter);

    // Security headers
    app.use((req, res, next) => {
      res.header('X-Content-Type-Options', 'nosniff');
      res.header('X-Frame-Options', 'DENY');
      res.header('X-XSS-Protection', '1; mode=block');
      res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
      next();
    });

    // Static assets and view engine
    app.useStaticAssets(join(__dirname, '..', 'public'));
    app.setBaseViewsDir(join(__dirname, '..', 'email-templates'));
    app.setViewEngine('ejs');

    // CORS configuration
    app.enableCors({
      origin: process.env.NODE_ENV === 'production' 
        ? [process.env.CLIENT_SIDE_URI] 
        : ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'accesstoken', 'refreshtoken'],
    });

    // Global validation pipe
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
        disableErrorMessages: process.env.NODE_ENV === 'production',
        validationError: {
          target: false,
          value: false,
        },
      }),
    );

    // Global exception filter
    app.useGlobalFilters(new GlobalExceptionFilter());

    // Global logging interceptor
    app.useGlobalInterceptors(new LoggingInterceptor());

    // Graceful shutdown
    app.enableShutdownHooks();

    const port = configService.get<number>('PORT') || 4001;
    await app.listen(port);
    
    logger.log(`🚀 Users service running on: http://localhost:${port}`);
    logger.log(`📊 GraphQL Playground: http://localhost:${port}/graphql`);

  } catch (error) {
    logger.error('Failed to start application', error.stack);
    process.exit(1);
  }
}

bootstrap();