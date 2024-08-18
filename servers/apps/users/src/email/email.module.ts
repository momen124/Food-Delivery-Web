import { Module } from '@nestjs/common';
import { EmailService } from './email.service';
import { config } from 'rxjs';
import { ConfigService } from '@nestjs/config';

@Global()
@Module({
  import:[MailerModule.forRootAsync({
    useFactory:async (config: ConfigService) => ({
      transport:{
      host: config.get('SMTP_HOST'),
      secure: true,
      auth :{
        user: config.get('SMTP_MAIL'),
        pass: config.get('SMTP_PASSWORD'),
      },
    },
    defaults: {
      from: 'Becodemy'
    },
    template:{
      dir: join(__dirname, '../../../../servers/email-templates'),
      adapter: new EjsAdapter(),
      option: {
        strict:false,
      },
    },
    }),
    inject: [ConfigService]
  })]
  providers: [EmailService]
})
export class EmailModule {}
