import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
@Injectable()
export class CsrfService {
  private readonly logger = new Logger(CsrfService.name);
  private readonly secret: string;
  constructor(private readonly config: ConfigService) {
    this.secret = this.config.get<string>('CSRF_SECRET') || this.generateSecret();
  }
  generateToken(sessionId?: string): string {
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const identifier = sessionId || 'anonymous';
   
    const payload = `${identifier}:${timestamp}:${randomBytes}`;
    const hash = this.createHash(payload);
   
    return Buffer.from(`${payload}:${hash}`).toString('base64');
  }
  validateToken(token: string, sessionId?: string, maxAge: number = 60 * 60 * 1000): boolean {
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      const parts = decoded.split(':');
     
      if (parts.length !== 4) {
        return false;
      }
      const [identifier, timestampStr, randomBytes, hash] = parts;
      const timestamp = parseInt(timestampStr, 10);
      const expectedIdentifier = sessionId || 'anonymous';
      // Validate identifier
      if (identifier !== expectedIdentifier) {
        this.logger.warn('CSRF token identifier mismatch');
        return false;
      }
      // Validate timestamp
      const age = Date.now() - timestamp;
      if (age > maxAge) {
        this.logger.warn('CSRF token expired');
        return false;
      }
      // Validate hash
      const payload = `${identifier}:${timestampStr}:${randomBytes}`;
      const expectedHash = this.createHash(payload);
     
      if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expectedHash))) {
        this.logger.warn('CSRF token hash validation failed');
        return false;
      }
      return true;
    } catch (error) {
      this.logger.warn('CSRF token validation error', error.message);
      return false;
    }
  }
  private createHash(payload: string): string {
    return crypto
      .createHmac('sha256', this.secret)
      .update(payload)
      .digest('hex');
  }
  private generateSecret(): string {
    const secret = crypto.randomBytes(32).toString('hex');
    this.logger.warn('Generated new CSRF secret. Set CSRF_SECRET in environment variables for production.');
    return secret;
  }
}