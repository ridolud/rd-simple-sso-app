import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.docorator';

@Injectable()
export class AuthGuard implements CanActivate {
  private logger = new Logger(AuthGuard.name);

  constructor(
    private readonly authService: AuthService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    try {
      const req = context.switchToHttp().getRequest<Request>();
      const refreshToken = this.authService.refreshTokenFromReq(req);

      const { id, tokenId } = await this.authService.verifyRefreshToken(
        refreshToken,
        req.headers.origin,
      );

      req['user'] = id;
      // this.logger.log(req['user']);

      return true;
    } catch {
      if (!!isPublic) return true;
      throw new UnauthorizedException();
    }
  }
}
