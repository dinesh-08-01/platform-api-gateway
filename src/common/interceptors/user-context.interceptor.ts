import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';

/**
 * Interceptor to add user context headers to outgoing requests to microservices
 * This extracts user information from the JWT and forwards it to downstream services
 */
@Injectable()
export class UserContextInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // Add user context to request headers for forwarding to microservices
    if (user) {
      request.headers['x-user-id'] = user.userId;
      request.headers['x-user-email'] = user.email;
      request.headers['x-user-roles'] = JSON.stringify(user.roles || []);
      
      if (user.applicationId) {
        request.headers['x-tenant-id'] = user.applicationId;
      }
    }

    return next.handle();
  }
}
