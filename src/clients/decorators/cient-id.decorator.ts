import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CLIENT_ID_KEY = 'clientId';
export const ClientId = createParamDecorator(
  (_, context: ExecutionContext): string | undefined => {
    return context.switchToHttp().getRequest<Request>()[CLIENT_ID_KEY];
  },
);
