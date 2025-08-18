// src/config/configuration.ts
import { plainToClass, Transform } from 'class-transformer';
import { IsString, IsNotEmpty, IsUrl, IsEmail, validateSync, IsPort, IsOptional } from 'class-validator';

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
  @IsUrl()
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
  @Transform(({ value }) => parseInt(value))
  @IsPort()
  PORT?: number = 4001;

  @IsOptional()
  @IsString()
  NODE_ENV?: string = 'development';
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

// Configuration factory
export default () => ({
  port: parseInt(process.env.PORT, 10) || 4001,
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
});