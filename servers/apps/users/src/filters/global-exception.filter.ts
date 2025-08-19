import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { GqlArgumentsHost, GqlExceptionFilter } from '@nestjs/graphql';
import { Prisma } from '@prisma/client';

@Catch()
export class GlobalExceptionFilter implements GqlExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: any, host: ArgumentsHost) {
    const gqlHost = GqlArgumentsHost.create(host);
    const info = gqlHost.getInfo();
    const context = gqlHost.getContext();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let code = 'INTERNAL_ERROR';

    // Safe field name access
    const fieldName = info?.fieldName || 'unknown';

    // Log the error
    this.logger.error(
      `GraphQL Error in ${fieldName}: ${exception.message}`,
      exception.stack,
    );

    // Handle different types of exceptions
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const response = exception.getResponse();
      message = typeof response === 'string' ? response : (response as any).message || exception.message;
      code = this.getErrorCode(status);
    } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      // Handle Prisma errors
      const prismaError = this.handlePrismaError(exception);
      status = prismaError.status;
      message = prismaError.message;
      code = prismaError.code;
    } else if (exception instanceof Prisma.PrismaClientValidationError) {
      status = HttpStatus.BAD_REQUEST;
      message = 'Invalid data provided';
      code = 'VALIDATION_ERROR';
    } else if (exception.name === 'JsonWebTokenError') {
      status = HttpStatus.UNAUTHORIZED;
      message = 'Invalid token';
      code = 'INVALID_TOKEN';
    } else if (exception.name === 'TokenExpiredError') {
      status = HttpStatus.UNAUTHORIZED;
      message = 'Token expired';
      code = 'TOKEN_EXPIRED';
    } else if (exception.name === 'ValidationError') {
      status = HttpStatus.BAD_REQUEST;
      message = exception.message || 'Validation failed';
      code = 'VALIDATION_ERROR';
    } else if (exception.name === 'ThrottlerException' || exception.message?.includes('Too many requests')) {
      status = HttpStatus.TOO_MANY_REQUESTS;
      message = 'Too many requests, please try again later.';
      code = 'RATE_LIMITED';
    }

    // Return formatted error
    return new HttpException(
      {
        statusCode: status,
        message,
        code,
        timestamp: new Date().toISOString(),
        path: fieldName,
      },
      status,
    );
  }

  private getErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_REQUEST';
      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHORIZED';
      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN';
      case HttpStatus.NOT_FOUND:
        return 'NOT_FOUND';
      case HttpStatus.CONFLICT:
        return 'CONFLICT';
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'UNPROCESSABLE_ENTITY';
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'TOO_MANY_REQUESTS';
      default:
        return 'INTERNAL_ERROR';
    }
  }

  private handlePrismaError(exception: Prisma.PrismaClientKnownRequestError) {
    switch (exception.code) {
      case 'P2002':
        return {
          status: HttpStatus.CONFLICT,
          message: 'A record with this information already exists',
          code: 'DUPLICATE_RECORD',
        };
      case 'P2025':
        return {
          status: HttpStatus.NOT_FOUND,
          message: 'Record not found',
          code: 'RECORD_NOT_FOUND',
        };
      case 'P2003':
        return {
          status: HttpStatus.BAD_REQUEST,
          message: 'Foreign key constraint failed',
          code: 'FOREIGN_KEY_ERROR',
        };
      case 'P2014':
        return {
          status: HttpStatus.BAD_REQUEST,
          message: 'Invalid data relationship',
          code: 'INVALID_RELATIONSHIP',
        };
      default:
        return {
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Database operation failed',
          code: 'DATABASE_ERROR',
        };
    }
  }
}