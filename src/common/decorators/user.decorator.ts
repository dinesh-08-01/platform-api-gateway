import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Custom decorator to extract user from request
 * Usage: @User() user: any
 */
export const User = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
