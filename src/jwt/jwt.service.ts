import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  IAccessPayload,
  IAccessToken,
} from 'src/jwt/interfaces/access-token.interface';
import {
  IEmailPayload,
  IEmailToken,
} from 'src/jwt/interfaces/email-token.interface';
import {
  IRefreshPayload,
  IRefreshToken,
} from 'src/jwt/interfaces/refresh-token.interface';
import * as jwt from 'jsonwebtoken';
import { v4 } from 'uuid';
import { Client, User } from '@prisma/client';
import { IJwtConfig } from 'src/configs/interfaces/jwt-config.interface';
import { ConfigKey } from 'src/configs/config';
import { TokenTypeEnum } from './types/token-type.enum';
import { IAppConfig } from 'src/configs/interfaces/app-config.interface';
import {
  IClientPayload,
  IClientToken,
} from './interfaces/client-token.interface';
import { ApiBadRequestException } from 'src/utils/exeptions/api-bad-request.exception';

@Injectable()
export class JwtService {
  private config: IJwtConfig;
  private readonly issuer: string;
  private readonly domain: string;

  constructor(private readonly configService: ConfigService) {
    const appConfig = this.configService.get<IAppConfig>(ConfigKey.App);
    this.config = this.configService.get<IJwtConfig>(ConfigKey.Jwt);

    this.issuer = appConfig.domain;
    this.domain = appConfig.domain;
  }

  private static async generateTokenAsync(
    payload: IAccessPayload | IEmailPayload | IRefreshPayload | IClientPayload,
    secret: string,
    options: jwt.SignOptions,
  ): Promise<string> {
    return new Promise((resolve, rejects) => {
      jwt.sign(payload, secret, options, (error, token) => {
        if (error) {
          rejects(error);
          return;
        }
        resolve(token);
      });
    });
  }

  private static async verifyTokenAsync<T>(
    token: string,
    secret: string,
    options: jwt.VerifyOptions,
  ): Promise<T> {
    return new Promise((resolve, rejects) => {
      jwt.verify(token, secret, options, (error, payload: T) => {
        if (error) {
          rejects(error);
          return;
        }
        resolve(payload);
      });
    });
  }

  private static async throwBadRequest<
    T extends IAccessToken | IRefreshToken | IEmailToken,
  >(promise: Promise<T>): Promise<T> {
    try {
      return await promise;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new ApiBadRequestException('Token expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new ApiBadRequestException('Invalid token');
      }
      throw new InternalServerErrorException(error);
    }
  }

  public async generateToken<
    T extends IAccessPayload | IRefreshPayload | IEmailPayload | IClientPayload,
  >(
    payload: T,
    tokenType: TokenTypeEnum,
    domain?: string | null,
  ): Promise<string> {
    const jwtOptions: jwt.SignOptions = {
      issuer: this.issuer,
      audience: domain ?? this.domain,
      algorithm: 'HS256',
    };

    let token: string;

    switch (tokenType) {
      case TokenTypeEnum.ACCESS:
        const { secret: accessSecret, time: accessTime } = this.config.access;
        token = await JwtService.generateTokenAsync(
          { id: payload.id },
          accessSecret,
          {
            ...jwtOptions,
            expiresIn: accessTime,
          },
        );
        break;
      case TokenTypeEnum.CLIENT:
        const { secret: clientSecret, time: clientTime } = this.config.client;
        const clientPayload = payload as IClientPayload;
        token = await JwtService.generateTokenAsync(
          { id: clientPayload.id, redirectUrl: clientPayload.redirectUrl },
          clientSecret,
          {
            ...jwtOptions,
            expiresIn: clientTime,
          },
        );
        break;
      case TokenTypeEnum.REFRESH:
        const { secret: refreshSecret, time: refreshTime } =
          this.config.refresh;
        const refreshPayload = payload as IRefreshPayload;
        token = await JwtService.generateTokenAsync(
          {
            id: refreshPayload.id,
            tokenId: refreshPayload.tokenId ?? v4(),
          },
          refreshSecret,
          {
            ...jwtOptions,
            expiresIn: refreshTime,
          },
        );
        break;
      case TokenTypeEnum.CONFIRMATION:
      case TokenTypeEnum.RESET_PASSWORD:
        const { secret, time } = this.config[tokenType];
        token = await JwtService.generateTokenAsync(
          { id: payload.id },
          secret,
          {
            ...jwtOptions,
            expiresIn: time,
          },
        );
        break;
    }

    return token;
  }

  public async verifyToken<
    T extends IAccessToken | IRefreshToken | IEmailToken | IClientToken,
  >(token: string, tokenType: TokenTypeEnum): Promise<T> {
    const jwtOptions: jwt.VerifyOptions = {
      issuer: this.issuer,
      audience: new RegExp(this.domain),
      algorithms: ['HS256'],
    };

    switch (tokenType) {
      case TokenTypeEnum.ACCESS:
        const { secret: accessSecret, time: accessTime } = this.config.access;
        return JwtService.throwBadRequest(
          JwtService.verifyTokenAsync(token, accessSecret, {
            ...jwtOptions,
            maxAge: accessTime,
          }),
        );
      case TokenTypeEnum.CLIENT:
        const { secret: clientSecret, time: clientTime } = this.config.client;
        return JwtService.throwBadRequest(
          JwtService.verifyTokenAsync(token, clientSecret, {
            ...jwtOptions,
            maxAge: clientTime,
          }),
        );
      case TokenTypeEnum.REFRESH:
      case TokenTypeEnum.CONFIRMATION:
      case TokenTypeEnum.RESET_PASSWORD:
        const { secret, time } = this.config[tokenType];
        return JwtService.throwBadRequest(
          JwtService.verifyTokenAsync(token, secret, {
            ...jwtOptions,
            maxAge: time,
          }),
        );
    }
  }
}
