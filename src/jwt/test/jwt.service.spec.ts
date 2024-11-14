import { faker } from '@faker-js/faker/.';
import { ConfigService } from '@nestjs/config';
import { TestingModule, Test } from '@nestjs/testing';
import { User } from '@prisma/client';
import { isJWT } from 'class-validator';
import { randomUUID } from 'crypto';
import { config } from 'process';
import { promisify } from 'util';
import { IAccessToken } from '../interfaces/access-token.interface';
import { IEmailToken } from '../interfaces/email-token.interface';
import { IRefreshToken } from '../interfaces/refresh-token.interface';
import { JwtService } from '../jwt.service';
import { TokenTypeEnum } from '../types/token-type.enum';
import { UserRoleEnums } from 'src/users/types/user-role.enum';
import { IAppConfig } from 'src/configs/interfaces/app-config.interface';
import { ConfigKey } from 'src/configs/config';
import { IJwtConfig } from 'src/configs/interfaces/jwt-config.interface';
import { sign } from 'jsonwebtoken';
import { ConfigsModule } from 'src/configs/config.module';

describe('JwtService', () => {
  let module: TestingModule;
  let service: JwtService;
  let appConfig: IAppConfig;
  let jwtConfig: IJwtConfig;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [ConfigsModule],
      providers: [JwtService],
    }).compile();

    service = module.get<JwtService>(JwtService);

    const configService = module.get<ConfigService>(ConfigService);
    appConfig = configService.get<IAppConfig>(ConfigKey.App);
    jwtConfig = configService.get<IJwtConfig>(ConfigKey.Jwt);
  });

  const mockUser1: User = {
    id: randomUUID(),
    name: faker.internet.displayName(),
    password: faker.internet.password(),
    email: faker.internet.email(),
    createdAt: new Date(),
    confirmed: true,
    role: UserRoleEnums.USER,
  };

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('access tokens', () => {
    let token: string;

    it('should generate a token', async () => {
      token = await service.generateToken(mockUser1, TokenTypeEnum.ACCESS);
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should verify a token', async () => {
      const decoded = await service.verifyToken<IAccessToken>(
        token,
        TokenTypeEnum.ACCESS,
      );
      expect(decoded).toBeDefined();
      expect(decoded.id).toEqual(mockUser1.id);
      expect(decoded.exp).toBeDefined();
    });

    it('should throw an error if the token is invalid', async () => {
      const invalidToken = token + 'invalid';
      await expect(
        service.verifyToken<IAccessToken>(invalidToken, TokenTypeEnum.ACCESS),
      ).rejects.toThrow('Invalid token');
    });

    it('should throw an error if the token is expired', async () => {
      const expiredToken = sign(
        {
          id: mockUser1.id,
          version: 1,
        },
        jwtConfig.confirmation.secret,
        {
          expiresIn: 1,
          issuer: appConfig.domain,
          audience: appConfig.domain,
          subject: mockUser1.email,
        },
      );
      const timeout = promisify(setTimeout);
      await timeout(1001);
      await expect(
        service.verifyToken<IEmailToken>(
          expiredToken,
          TokenTypeEnum.CONFIRMATION,
        ),
      ).rejects.toThrow('Token expired');
    });
  });

  describe('refresh tokens', () => {
    let token: string;

    it('should generate a token', async () => {
      token = await service.generateToken(mockUser1, TokenTypeEnum.REFRESH);
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should verify a token', async () => {
      const decoded = await service.verifyToken<IRefreshToken>(
        token,
        TokenTypeEnum.REFRESH,
      );
      expect(decoded).toBeDefined();
      expect(decoded.id).toEqual(mockUser1.id);
      expect(decoded.tokenId).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should throw an error if the token is invalid', async () => {
      const invalidToken = token + 'invalid';
      await expect(
        service.verifyToken<IRefreshToken>(invalidToken, TokenTypeEnum.REFRESH),
      ).rejects.toThrow('Invalid token');
    });
  });

  describe('confirmation tokens', () => {
    let token: string;

    it('should generate a token', async () => {
      token = await service.generateToken(
        mockUser1,
        TokenTypeEnum.CONFIRMATION,
      );
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should verify a token', async () => {
      const decoded = await service.verifyToken<IEmailToken>(
        token,
        TokenTypeEnum.CONFIRMATION,
      );
      expect(decoded).toBeDefined();
      expect(decoded.id).toEqual(mockUser1.id);
      expect(decoded.exp).toBeDefined();
    });

    it('should throw an error if the token is invalid', async () => {
      const invalidToken = token + 'invalid';
      await expect(
        service.verifyToken<IEmailToken>(
          invalidToken,
          TokenTypeEnum.CONFIRMATION,
        ),
      ).rejects.toThrow('Invalid token');
    });
  });
});
