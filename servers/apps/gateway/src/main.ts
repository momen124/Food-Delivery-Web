import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('GatewayBootstrap');
  
  try {
    logger.log('Starting API Gateway...');
    
    const app = await NestFactory.create(AppModule, {
      logger: ['log', 'error', 'warn', 'debug'],
    });

    // Enable CORS for development
    app.enableCors({
      origin: ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'accesstoken', 'refreshtoken'],
    });

    const port = process.env.GATEWAY_PORT || 4000;
    await app.listen(port);
    
    logger.log(`🚀 API Gateway running on: http://localhost:${port}`);
    logger.log(`📊 GraphQL Playground: http://localhost:${port}/graphql`);
    logger.log(`🔍 Health Check: http://localhost:${port}/health`);
    
  } catch (error) {
    logger.error('Failed to start API Gateway', error.stack);
    process.exit(1);
  }
}

bootstrap();