import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { CsrfService } from './csrf.service';
export const SkipCsrf = () => Reflector.createDecorator<boolean>();
@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(
    private readonly csrfService: CsrfService,
    private readonly reflector: Reflector,
  ) {}
  canActivate(context: ExecutionContext): boolean {
    // Check if CSRF should be skipped for this handler
    const skipCsrf = this.reflector.getAllAndOverride<boolean>('skipCsrf', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (skipCsrf) {
      return true;
    }
    const gqlCtx = GqlExecutionContext.create(context);
    const { req } = gqlCtx.getContext();
    const operation = gqlCtx.getInfo().fieldName;
    // Skip CSRF for read-only operations
    const readOnlyOperations = ['getLoggedInUser', 'getUsers'];
    if (readOnlyOperations.includes(operation)) {
      return true;
    }
    // Check for CSRF token in headers
    const csrfToken = req.headers['x-csrf-token'] || req.headers['csrf-token'];
   
    if (!csrfToken) {
      throw new ForbiddenException('CSRF token is required for this operation');
    }
    const sessionId = req.user?.id || req.sessionID;
    const isValid = this.csrfService.validateToken(csrfToken, sessionId);
    if (!isValid) {
      throw new ForbiddenException('Invalid CSRF token');
    }
    return true;
  }
}