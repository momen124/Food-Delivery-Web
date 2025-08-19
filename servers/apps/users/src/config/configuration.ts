import { plainToClass, Transform } from 'class-transformer';
import { IsString, IsNotEmpty, IsUrl, IsEmail, validateSync, IsOptional, IsNumber } from 'class-validator';

export class EnvironmentVariables {
  @IsNotEmpty()
  @IsString()
  DATABASE_URL: string;

  @IsNotEmpty()
  @IsString()
  ACTIVATION_SECRET: string;

  @IsNotEmpty()
  @IsString()
  ACCESS_TOKEN_SECRET: string;

  @IsNotEmpty()
  @IsString()
  REFRESH_TOKEN_SECRET: string;

  @IsNotEmpty()
  @IsString()
  FORGOT_PASSWORD_SECRET: string;

  @IsNotEmpty()
  @IsUrl({ require_tld: false }) // Allow localhost without TLD
  CLIENT_SIDE_URI: string;

  @IsNotEmpty()
  @IsString()
  SMTP_HOST: string;

  @IsNotEmpty()
  @IsEmail()
  SMTP_MAIL: string;

  @IsNotEmpty()
  @IsString()
  SMTP_PASSWORD: string;

  @IsOptional()
  @Transform(({ value }) => (typeof value === 'string' ? parseInt(value, 10) : value))
  @IsNumber()
  @IsOptional()
  PORT: number = 4001;

  @IsOptional()
  @IsString()
  NODE_ENV: string = 'development';

  @IsOptional()
  @IsString()
  CSRF_SECRET?: string;

  @IsOptional()
  @IsNumber()
  RATE_LIMIT_TTL: number = 60;

  @IsOptional()
  @IsNumber()
  RATE_LIMIT_MAX: number = 100;

  @IsOptional()
  @IsString()
  SESSION_SECRET?: string;

  @IsOptional()
  @IsString()
  TWO_FACTOR_APP_NAME: string = 'Food Delivery';
}

export function validateConfig(config: Record<string, unknown>) {
  const validatedConfig = plainToClass(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    const errorMessages = errors.map(error => {
      const constraints = Object.values(error.constraints || {});
      return `${error.property}: ${constraints.join(', ')}`;
    }).join('\n');

    throw new Error(`Configuration validation failed:\n${errorMessages}`);
  }

  return validatedConfig;
}

export default () => ({
  port: parseInt(process.env.PORT || '4001', 10),
  database: {
    url: process.env.DATABASE_URL,
  },
  jwt: {
    activationSecret: process.env.ACTIVATION_SECRET,
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
    forgotPasswordSecret: process.env.FORGOT_PASSWORD_SECRET,
  },
  smtp: {
    host: process.env.SMTP_HOST,
    mail: process.env.SMTP_MAIL,
    password: process.env.SMTP_PASSWORD,
  },
  client: {
    sideUri: process.env.CLIENT_SIDE_URI,
  },
  app: {
    nodeEnv: process.env.NODE_ENV || 'development',
  },
  rateLimit: {
    ttl: parseInt(process.env.RATE_LIMIT_TTL || '60', 10),
    max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  },
  csrf: {
    secret: process.env.CSRF_SECRET,
  },
  session: {
    secret: process.env.SESSION_SECRET,
  },
  twoFactor: {
    appName: process.env.TWO_FACTOR_APP_NAME || 'Food Delivery',
  },
});