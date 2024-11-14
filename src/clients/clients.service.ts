import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client } from '@prisma/client';
import { randomBytes } from 'crypto';
import { Request, Response } from 'express';
import { ConfigKey, Environment } from 'src/configs/config';
import { IAppConfig } from 'src/configs/interfaces/app-config.interface';
import { ICookiesConfig } from 'src/configs/interfaces/cookies-config.interface';
import {
  IClientPayload,
  IClientToken,
} from 'src/jwt/interfaces/client-token.interface';
import { JwtService } from 'src/jwt/jwt.service';
import { TokenTypeEnum } from 'src/jwt/types/token-type.enum';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class ClientsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async findOne(id: string) {
    return await this.prisma.client.findFirst({
      where: { id },
      include: {
        redirectUrls: true,
      },
    });
  }

  async isExist(id: string) {
    return Boolean(await this.prisma.client.findFirst({ where: { id } }));
  }

  async findOneByCredentials(id: string, secret: string) {
    return await this.prisma.client.findFirst({
      where: { id, secret },
      include: { redirectUrls: true },
    });
  }

  async generate(redirectUrls?: string[]) {
    return await this.prisma.client.create({
      data: {
        redirectUrls: {
          createMany: {
            data: redirectUrls.map((url) => ({ url })),
          },
        },
        secret: Buffer.from(randomBytes(32)).toString('hex'),
      },
      include: {
        redirectUrls: true,
      },
    });
  }

  async revoke(id: string) {
    return await this.prisma.client.update({
      where: { id },
      data: {
        secret: Buffer.from(randomBytes(32)).toString('hex'),
      },
    });
  }

  async updateRedirectUrl(id: string, redirectUrls: string[]) {
    await this.prisma.clientRedirectUrl.deleteMany({ where: { clientId: id } });
    return await this.prisma.client.update({
      where: { id },
      data: {
        redirectUrls: {
          createMany: {
            data: redirectUrls.map((url) => ({ url })),
          },
        },
      },
      include: { redirectUrls: true },
    });
  }

  async remove(id: string) {
    return await this.prisma.client.delete({ where: { id } });
  }

  public async decodeTokenFromReq(req: Request) {
    const cookieConfig = this.configService.getOrThrow<ICookiesConfig>(
      ConfigKey.Cookies,
    );
    const token = req.signedCookies[cookieConfig.clientId];

    if (!token) {
      throw new UnauthorizedException('Client token not defind!');
    }
    return await this.jwtService.verifyToken<IClientToken>(
      token,
      TokenTypeEnum.CLIENT,
    );
  }

  public async generateToken(
    client: Client,
    domain?: string,
    redirectUrl?: string,
  ): Promise<string> {
    return this.jwtService.generateToken<IClientPayload>(
      { id: client.id, redirectUrl },
      TokenTypeEnum.CLIENT,
      domain,
    );
  }

  saveTokenCookie(res: Response, clientToken: string): Response {
    const appConfig = this.configService.getOrThrow<IAppConfig>(ConfigKey.App);
    const cookieConfig = this.configService.getOrThrow<ICookiesConfig>(
      ConfigKey.Cookies,
    );

    return res.cookie('app-client-token', clientToken, {
      secure: appConfig.env != Environment.test,
      httpOnly: true,
      sameSite: 'strict',
      signed: true,
      expires: new Date(Date.now() + cookieConfig.time),
    });
  }
}
