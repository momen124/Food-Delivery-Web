// src/main.ts
import { NestFactory } from '@nestjs/core';
import { UsersModule } from './users.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { MongoDBService } from './mongodb.service';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(UsersModule);
  
  // Ensure MongoDB connection is established before starting the server
  const mongoDBService = app.get(MongoDBService);
  
  try {
    await mongoDBService.connect();
  } catch (error) {
    console.error('Could not connect to MongoDB, shutting down the application.');
    process.exit(1); // Exit with error code
  }

  app.useStaticAssets(join(__dirname, '..', 'public'));
  app.setBaseViewsDir(join(__dirname, '..', 'servers/email-templates'));
  app.setViewEngine('ejs');
  
  await app.listen(4001);
  console.log('Application is running on: http://localhost:4001');
}

bootstrap();
