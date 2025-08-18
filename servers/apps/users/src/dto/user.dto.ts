import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, MinLength, IsOptional, Matches } from 'class-validator';
import { Transform } from 'class-transformer';

// Sanitization helper functions
const sanitizeString = (value: string): string => {
  if (typeof value !== 'string') return value;
  return value
    .trim()
    .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
    .substring(0, 255); // Limit length
};

const sanitizeName = (value: string): string => {
  if (typeof value !== 'string') return value;
  return value
    .trim()
    .replace(/[^a-zA-Z\s\u00C0-\u017F]/g, '') // Only letters and accented characters
    .substring(0, 100);
};

const sanitizePhoneNumber = (value: string): string => {
  if (typeof value !== 'string') return value;
  return value
    .trim()
    .replace(/[^\d+\-\s()]/g, '') // Only digits, +, -, spaces, parentheses
    .substring(0, 20);
};

@InputType()
export class RegisterDto {
  @Field()
  @IsNotEmpty({ message: 'Name is required.' })
  @IsString({ message: 'Name must be a string.' })
  @Transform(({ value }) => sanitizeName(value))
  @Matches(/^[a-zA-Z\s\u00C0-\u017F]{2,100}$/, {
    message: 'Name must contain only letters and spaces, and be 2-100 characters long.'
  })
  name: string;

  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
  })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email is invalid.' })
  @Transform(({ value }) => sanitizeString(value).toLowerCase())
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString({ message: 'Phone number must be a string.' })
  @Transform(({ value }) => value ? sanitizePhoneNumber(value) : value)
  @Matches(/^[\d+\-\s()]{10,20}$/, {
    message: 'Phone number must be 10-20 characters and contain only digits, +, -, spaces, or parentheses.'
  })
  phone_number?: string;
}

@InputType()
export class ActivationDto {
  @Field()
  @IsNotEmpty({ message: 'Activation Token is required.' })
  @IsString({ message: 'Activation Token must be a string.' })
  @Transform(({ value }) => sanitizeString(value))
  activationToken: string;

  @Field()
  @IsNotEmpty({ message: 'Activation Code is required.' })
  @IsString({ message: 'Activation Code must be a string.' })
  @Matches(/^\d{4}$/, { message: 'Activation code must be exactly 4 digits.' })
  activationCode: string;
}

@InputType()
export class LoginDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email must be valid.' })
  @Transform(({ value }) => sanitizeString(value).toLowerCase())
  email: string;

  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  @IsString({ message: 'Password must be a string.' })
  password: string;
}

@InputType()
export class ForgotPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email must be valid.' })
  @Transform(({ value }) => sanitizeString(value).toLowerCase())
  email: string;
}

@InputType()
export class ResetPasswordDto {
  @Field()
  @IsNotEmpty({ message: 'Password is required.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
  })
  password: string;

  @Field()
  @IsNotEmpty({ message: 'Activation Token is required.' })
  @IsString({ message: 'Activation Token must be a string.' })
  @Transform(({ value }) => sanitizeString(value))
  activationToken: string;
}