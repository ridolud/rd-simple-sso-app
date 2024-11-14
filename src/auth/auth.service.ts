import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  Injectable,
  Inject,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { Prisma, User } from '@prisma/client';
import { plainToInstance } from 'class-transformer';
import { IEmailToken } from 'src/jwt/interfaces/email-token.interface';
import {
  IRefreshPayload,
  IRefreshToken,
} from 'src/jwt/interfaces/refresh-token.interface';
import { JwtService } from 'src/jwt/jwt.service';
import { TokenTypeEnum } from 'src/jwt/types/token-type.enum';
import { UsersService } from 'src/users/users.service';
import { SignUpDto } from './dto/sign-up.dto';
import { ConfirmEmailDto } from './dto/confirm-email.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { EmailDto } from './dto/email.dto';
import { PasswordDto } from './dto/password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SignInDto } from './dto/sign-in.dto';
import * as dayjs from 'dayjs';
import { Cache } from 'cache-manager';
import { MailService } from 'src/mail/mail.service';
import { Request, Response } from 'express';
import { IAppConfig } from 'src/configs/interfaces/app-config.interface';
import { ICookiesConfig } from 'src/configs/interfaces/cookies-config.interface';
import { ConfigService } from '@nestjs/config';
import { ConfigKey, Environment } from 'src/configs/config';
import {
  IAccessPayload,
  IAccessToken,
} from 'src/jwt/interfaces/access-token.interface';

@Injectable()
export class AuthService {
  private appConfig: IAppConfig;
  private cookieConfig: ICookiesConfig;

  constructor(
    @Inject(CACHE_MANAGER)
    private readonly cacheManager: Cache,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
  ) {
    this.appConfig = this.configService.get<IAppConfig>(ConfigKey.App);
    this.cookieConfig = this.configService.get<ICookiesConfig>(
      ConfigKey.Cookies,
    );
  }

  public async signUp(input: SignUpDto, domain?: string): Promise<void> {
    const { name, email, password } = input;

    if (await this.usersService.isRegistered(email))
      throw new BadRequestException('Email already register');

    const user = await this.usersService.create({ name, email, password });

    const confirmationToken = await this.jwtService.generateToken(
      user,
      TokenTypeEnum.CONFIRMATION,
      domain,
    );

    this.mailService.sendConfirmationEmail(user, confirmationToken);
  }

  public async confirmEmail(
    input: ConfirmEmailDto,
    domain?: string,
  ): Promise<AuthResponseDto> {
    const { confirmationToken } = input;
    const { id } = await this.jwtService.verifyToken<IEmailToken>(
      confirmationToken,
      TokenTypeEnum.CONFIRMATION,
    );
    const user = await this.usersService.confirmEmail(id);
    const [accessToken, refreshToken] = await this.generateAuthTokens(
      user,
      domain,
    );
    return plainToInstance(AuthResponseDto, {
      user,
      accessToken,
      refreshToken,
    });
  }

  public async signIn(
    input: SignInDto,
    domain?: string,
  ): Promise<AuthResponseDto> {
    const { email, password } = input;
    const user = await this.usersService.findOneByCredentials(email, password);

    if (!user.confirmed) {
      const confirmationToken = await this.jwtService.generateToken(
        user,
        TokenTypeEnum.CONFIRMATION,
        domain,
      );

      this.mailService.sendConfirmationEmail(user, confirmationToken);

      throw new UnauthorizedException(
        'Please confirm your email, a new email has been sent',
      );
    }

    const [accessToken, refreshToken] = await this.generateAuthTokens(
      user,
      domain,
    );

    return plainToInstance(AuthResponseDto, {
      user,
      accessToken,
      refreshToken,
    });
  }

  public async verifyRefreshToken(token: string, domain?: string) {
    const result = await this.jwtService.verifyToken<IRefreshToken>(
      token,
      TokenTypeEnum.REFRESH,
    );
    await this.checkIfTokenIsBlacklisted(result.id, result.tokenId);
    return result;
  }

  public async verifyAccessToken(token: string, domain?: string) {
    return await this.jwtService.verifyToken<IAccessToken>(
      token,
      TokenTypeEnum.ACCESS,
    );
  }

  public async verifyResetPasswordToken(token: string, domain?: string) {
    return await this.jwtService.verifyToken<IEmailToken>(
      token,
      TokenTypeEnum.RESET_PASSWORD,
    );
  }

  public async refreshTokenAccess(
    refreshToken: string,
    domain?: string,
  ): Promise<AuthResponseDto> {
    const { id, tokenId } = await this.verifyRefreshToken(refreshToken, domain);
    const user = await this.usersService.findOne(id);
    const [accessToken, newRefreshToken] = await this.generateAuthTokens(
      user,
      domain,
      tokenId,
    );
    return plainToInstance(AuthResponseDto, {
      user,
      accessToken,
      refreshToken,
    });
  }

  public async logout(refreshToken: string): Promise<void> {
    const { id, tokenId, exp } =
      await this.jwtService.verifyToken<IRefreshToken>(
        refreshToken,
        TokenTypeEnum.REFRESH,
      );
    await this.blacklistToken(id, tokenId, exp);
  }

  public async resetPasswordEmail(
    input: EmailDto,
    domain?: string,
  ): Promise<void> {
    try {
      const user = await this.usersService.findOneByEmail(input.email);
      if (!user) return;

      const resetToken = await this.jwtService.generateToken(
        user,
        TokenTypeEnum.RESET_PASSWORD,
        domain,
      );

      this.mailService.sendResetPasswordEmail(user, resetToken);
      return;
    } catch (_) {
      return;
    }
  }

  public async resetPassword(input: ResetPasswordDto): Promise<void> {
    const { newPassword, resetToken } = input;
    const { id } = await this.verifyResetPasswordToken(resetToken);

    const user = await this.usersService.findOne(id);
    if (!user) throw new NotFoundException('user not found!');

    await this.usersService.resetPassword(user.id, newPassword);
  }

  public async updatePassword(
    userId: string,
    dto: PasswordDto,
    domain?: string,
  ): Promise<AuthResponseDto> {
    const { password } = dto;

    const user = await this.usersService.findOne(userId);
    if (!user) throw new NotFoundException('user not found!');

    await this.usersService.resetPassword(user.id, password);
    const [accessToken, refreshToken] = await this.generateAuthTokens(
      user,
      domain,
    );

    return plainToInstance(AuthResponseDto, {
      user,
      accessToken,
      refreshToken,
    });
  }

  private async checkIfTokenIsBlacklisted(
    userId: string,
    tokenId: string,
  ): Promise<void> {
    const time = await this.cacheManager.get<number>(
      `blacklist:${userId}:${tokenId}`,
    );

    if (time) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private async blacklistToken(
    userId: string,
    tokenId: string,
    exp: number,
  ): Promise<void> {
    const now = dayjs().unix();
    const ttl = (exp - now) * 1000;

    if (ttl > 0) {
      await this.cacheManager.set(`blacklist:${userId}:${tokenId}`, now, ttl);
    }
  }

  public async generateAuthTokens(
    user: User,
    domain?: string,
    tokenId?: string,
  ): Promise<[string, string]> {
    return Promise.all([
      this.jwtService.generateToken<IAccessPayload>(
        { id: user.id },
        TokenTypeEnum.ACCESS,
        domain,
      ),
      this.jwtService.generateToken<IRefreshPayload>(
        { id: user.id, tokenId },
        TokenTypeEnum.REFRESH,
        domain,
      ),
    ]);
  }

  refreshTokenFromReq(req: Request): string {
    const token: string | undefined =
      req.signedCookies[this.cookieConfig.refreshId];

    if (!token) {
      throw new UnauthorizedException();
    }

    return token;
  }

  saveRefreshCookie(res: Response, refreshToken: string): Response {
    return res.cookie(this.cookieConfig.refreshId, refreshToken, {
      secure: this.appConfig.env != Environment.test,
      httpOnly: true,
      sameSite: 'strict',
      signed: true,
      expires: new Date(Date.now() + this.cookieConfig.time),
    });
  }
}
