import { Injectable, Logger } from '@nestjs/common';
import { MongoClient } from 'mongodb';

@Injectable()
export class MongoDBService {
  private readonly logger = new Logger(MongoDBService.name);
  private client: MongoClient;

  constructor() {
    this.connect();
  }

  async connect() {
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

  getClient() {
    return this.client;
  }
}
