import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ClientsService } from '../clients.service';
import { CLIENT_ID_KEY } from '../decorators/cient-id.decorator';
import { CLIENT_REDIRECT_URL_KEY } from '../decorators/cient-redirect-url.decorator';

@Injectable()
export class ClientGuard implements CanActivate {
  private logger = new Logger(ClientGuard.name);

  constructor(private readonly clientsService: ClientsService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    const { id: clientId, redirectUrl } =
      await this.clientsService.decodeTokenFromReq(req);

    // this.logger.debug({ clientId, redirectUrl });

    if (!clientId || !redirectUrl)
      throw new UnauthorizedException('Invalid client token!');

    req[CLIENT_ID_KEY] = clientId;
    req[CLIENT_REDIRECT_URL_KEY] = redirectUrl;

    return true;
  }
}
