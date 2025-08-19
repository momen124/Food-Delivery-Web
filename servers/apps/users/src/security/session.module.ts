import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaService } from '../../../../prisma/prisma.service';
import { SessionService } from './session.service';

@Module({
  imports: [ConfigModule],
  providers: [SessionService, PrismaService],
  exports: [SessionService],
})
export class SessionModule {}