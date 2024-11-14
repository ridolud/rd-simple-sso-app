import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CLIENT_REDIRECT_URL_KEY = 'clientRedirectUrl';
export const ClientRedirectUrl = createParamDecorator(
  (_, context: ExecutionContext): string | undefined => {
    return context.switchToHttp().getRequest<Request>()[
      CLIENT_REDIRECT_URL_KEY
    ];
  },
);
