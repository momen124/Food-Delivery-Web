import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { PrismaService } from 'prisma/Prisma.service';
@Injectable()
export class TwoFactorAuthService {
  private readonly logger = new Logger(TwoFactorAuthService.name);
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}
  async generateTwoFactorSecret(userId: string): Promise<{ secret: string; qrCodeUrl: string }> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });
      if (!user) {
        throw new BadRequestException('User not found');
      }
      const secret = speakeasy.generateSecret({
        name: `Food Delivery (${user.email})`,
        issuer: 'Food Delivery App',
        length: 32,
      });
      // Store secret temporarily (not activated yet)
      await this.prisma.twoFactorAuth.upsert({
        where: { userId },
        create: {
          userId,
          secret: secret.base32,
          isEnabled: false,
          backupCodes: this.generateBackupCodes(),
        },
        update: {
          secret: secret.base32,
          isEnabled: false,
          backupCodes: this.generateBackupCodes(),
        },
      });
      const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
      return {
        secret: secret.base32,
        qrCodeUrl,
      };
    } catch (error) {
      this.logger.error(`Failed to generate 2FA secret for user ${userId}`, error.stack);
      throw error;
    }
  }
  async enableTwoFactor(userId: string, token: string): Promise<{ backupCodes: string[] }> {
    try {
      const twoFactorAuth = await this.prisma.twoFactorAuth.findUnique({
        where: { userId },
      });
      if (!twoFactorAuth) {
        throw new BadRequestException('2FA not set up for this user');
      }
      const isValid = speakeasy.totp.verify({
        secret: twoFactorAuth.secret,
        token,
        window: 2,
      });
      if (!isValid) {
        throw new BadRequestException('Invalid 2FA token');
      }
      // Enable 2FA
      await this.prisma.twoFactorAuth.update({
        where: { userId },
        data: {
          isEnabled: true,
          enabledAt: new Date(),
        },
      });
      this.logger.log(`2FA enabled for user ${userId}`);
      return {
        backupCodes: JSON.parse(twoFactorAuth.backupCodes),
      };
    } catch (error) {
      this.logger.error(`Failed to enable 2FA for user ${userId}`, error.stack);
      throw error;
    }
  }
  async verifyTwoFactor(userId: string, token: string): Promise<boolean> {
    try {
      const twoFactorAuth = await this.prisma.twoFactorAuth.findUnique({
        where: { userId },
      });
      if (!twoFactorAuth || !twoFactorAuth.isEnabled) {
        return false; // 2FA not enabled
      }
      // Check if it's a backup code
      const backupCodes = JSON.parse(twoFactorAuth.backupCodes);
      if (backupCodes.includes(token)) {
        // Use backup code (remove it after use)
        const updatedCodes = backupCodes.filter((code: string) => code !== token);
        await this.prisma.twoFactorAuth.update({
          where: { userId },
          data: {
            backupCodes: JSON.stringify(updatedCodes),
          },
        });
       
        this.logger.log(`Backup code used for user ${userId}`);
        return true;
      }
      // Verify TOTP token
      const isValid = speakeasy.totp.verify({
        secret: twoFactorAuth.secret,
        token,
        window: 2,
      });
      return isValid;
    } catch (error) {
      this.logger.error(`Failed to verify 2FA for user ${userId}`, error.stack);
      return false;
    }
  }
  async disableTwoFactor(userId: string, token: string): Promise<void> {
    try {
      const isValid = await this.verifyTwoFactor(userId, token);
     
      if (!isValid) {
        throw new BadRequestException('Invalid 2FA token');
      }
      await this.prisma.twoFactorAuth.update({
        where: { userId },
        data: {
          isEnabled: false,
          disabledAt: new Date(),
        },
      });
      this.logger.log(`2FA disabled for user ${userId}`);
    } catch (error) {
      this.logger.error(`Failed to disable 2FA for user ${userId}`, error.stack);
      throw error;
    }
  }
  async isTwoFactorEnabled(userId: string): Promise<boolean> {
    try {
      const twoFactorAuth = await this.prisma.twoFactorAuth.findUnique({
        where: { userId },
      });
      return twoFactorAuth?.isEnabled || false;
    } catch (error) {
      this.logger.error(`Failed to check 2FA status for user ${userId}`, error.stack);
      return false;
    }
  }
  private generateBackupCodes(): string {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
    }
    return JSON.stringify(codes);
  }
}