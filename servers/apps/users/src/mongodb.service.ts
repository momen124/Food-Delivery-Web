import { Injectable, Logger, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { MongoClient } from 'mongodb';

@Injectable()
export class MongoDBService implements OnModuleInit, OnApplicationShutdown {
  private readonly logger = new Logger(MongoDBService.name);
  private client: MongoClient;

  async onModuleInit() {
    const uri = process.env.DATABASE_URL;
    if (!uri) {
      this.logger.error('DATABASE_URL is not defined');
      throw new Error('DATABASE_URL is not defined');
    }

    try {
      this.client = new MongoClient(uri);
      await this.client.connect();
      this.logger.log('Connected to MongoDB');
    } catch (error) {
      this.logger.error('Failed to connect to MongoDB', error.stack);
      throw error;
    }
  }

  async onApplicationShutdown(signal?: string) {
    if (this.client) {
      await this.client.close();
      this.logger.log('Disconnected from MongoDB');
    }
  }

  getClient() {
    return this.client;
  }
}