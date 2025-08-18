// src/interceptors/logging.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const gqlContext = GqlExecutionContext.create(context);
    const info = gqlContext.getInfo();
    const { req } = gqlContext.getContext();

    const startTime = Date.now();
    const operation = info.fieldName;
    const variables = gqlContext.getArgs();

    // Sanitize variables for logging (remove sensitive data)
    const sanitizedVariables = this.sanitizeVariables(variables);

    this.logger.log(`📥 ${operation} - Started`, {
      operation,
      variables: sanitizedVariables,
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.connection.remoteAddress,
    });

    return next.handle().pipe(
      tap((data) => {
        const duration = Date.now() - startTime;
        this.logger.log(`✅ ${operation} - Completed in ${duration}ms`);
      }),
      catchError((error) => {
        const duration = Date.now() - startTime;
        this.logger.error(`❌ ${operation} - Failed in ${duration}ms: ${error.message}`);
        return throwError(() => error);
      }),
    );
  }

  private sanitizeVariables(variables: any): any {
    if (!variables || typeof variables !== 'object') {
      return variables;
    }

    const sensitiveFields = ['password', 'activationToken', 'activationCode'];
    const sanitized = { ...variables };

    // Recursively sanitize nested objects
    const sanitizeObject = (obj: any): any => {
      if (!obj || typeof obj !== 'object') return obj;
      
      const sanitizedObj = { ...obj };
      
      for (const key in sanitizedObj) {
        if (sensitiveFields.includes(key)) {
          sanitizedObj[key] = '[REDACTED]';
        } else if (typeof sanitizedObj[key] === 'object') {
          sanitizedObj[key] = sanitizeObject(sanitizedObj[key]);
        }
      }
      
      return sanitizedObj;
    };

    return sanitizeObject(sanitized);
  }
}