import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CsrfService } from './csrf.service';
import { CsrfGuard } from './csrf.guard';

@Module({
  imports: [ConfigModule],
  providers: [CsrfService, CsrfGuard],
  exports: [CsrfService, CsrfGuard],
})
export class CsrfModule {}