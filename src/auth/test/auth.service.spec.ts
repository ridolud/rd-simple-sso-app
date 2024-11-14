import { faker } from '@faker-js/faker';
import { CacheModule, CACHE_MANAGER } from '@nestjs/cache-manager';
import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TestingModule, Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import { User } from '@prisma/client';
import { hash } from 'bcrypt';
import { Cache } from 'cache-manager';
import { isJWT } from 'class-validator';
import { randomUUID } from 'crypto';
import { AuthService } from 'src/auth/auth.service';
import { CacheConfig } from 'src/configs/cache.config';
import { ConfigKey } from 'src/configs/config';
import { ConfigsModule } from 'src/configs/config.module';
import { ThrottlerConfig } from 'src/configs/throttler.config';
import { IRefreshToken } from 'src/jwt/interfaces/refresh-token.interface';
import { JwtModule } from 'src/jwt/jwt.module';
import { JwtService } from 'src/jwt/jwt.service';
import { TokenTypeEnum } from 'src/jwt/types/token-type.enum';
import { MailModule } from 'src/mail/mail.module';
import { MailService } from 'src/mail/mail.service';
import { UserRoleEnums } from 'src/users/types/user-role.enum';
import { UsersModule } from 'src/users/users.module';
import { UsersService } from 'src/users/users.service';

describe('AuthService', () => {
  let module: TestingModule,
    authService: AuthService,
    mailService: MailService,
    usersService: UsersService,
    jwtService: JwtService,
    cacheManager: Cache,
    baseUserPassword: string,
    baseUser: User;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        ConfigsModule,
        CacheModule.register({
          isGlobal: true,
          imports: [ConfigsModule],
          useClass: CacheConfig,
        }),
        // ThrottlerModule.forRootAsync({
        //   imports: [ConfigsModule],
        //   useClass: ThrottlerConfig,
        // }),
        MailModule,
        UsersModule,
        JwtModule,
      ],
      providers: [AuthService],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    mailService = module.get<MailService>(MailService);
    usersService = module.get<UsersService>(UsersService);
    jwtService = module.get<JwtService>(JwtService);
    cacheManager = module.get<Cache>(CACHE_MANAGER);

    jest.spyOn(mailService, 'sendEmail').mockImplementation();
    baseUserPassword = await hash(faker.internet.password(), 10);

    baseUser = {
      id: randomUUID(),
      name: faker.internet.displayName(),
      password: baseUserPassword,
      email: faker.internet.email(),
      createdAt: new Date(),
      confirmed: true,
      role: UserRoleEnums.USER,
    };
  });

  it('should be defined', () => {
    expect(module).toBeDefined();
    expect(authService).toBeDefined();
    expect(mailService).toBeDefined();
    expect(usersService).toBeDefined();
    expect(jwtService).toBeDefined();
    expect(cacheManager).toBeDefined();
  });

  describe('sign up', () => {
    it('should create a new user', async () => {
      jest.spyOn(mailService, 'sendConfirmationEmail').mockImplementation();
      jest.spyOn(usersService, 'create').mockResolvedValue({
        ...baseUser,
        password: await hash(baseUser.password, 10),
      });
      await expect(
        authService.signUp({
          name: baseUser.name,
          email: baseUser.email,
          password: baseUser.password,
        }),
      ).resolves.not.toThrow();

      expect(mailService.sendConfirmationEmail).toHaveBeenCalled();
    });

    it('should throw an error if email already registerd', async () => {
      jest
        .spyOn(usersService, 'create')
        .mockRejectedValueOnce(new BadRequestException());
      const password = faker.internet.password();
      await expect(
        authService.signUp({
          name: baseUser.name,
          email: baseUser.email,
          password: baseUser.password,
        }),
      ).rejects.toThrow();
    });
  });

  describe('confirm email', () => {
    let token: string;

    it('should create a confirmation token', async () => {
      token = await jwtService.generateToken(
        baseUser,
        TokenTypeEnum.CONFIRMATION,
      );
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should confirm the email', async () => {
      jest.spyOn(usersService, 'confirmEmail').mockResolvedValue({
        ...baseUser,
        password: await hash(baseUser.password, 10),
      });

      const result = await authService.confirmEmail({
        confirmationToken: token,
      });
      expect(result.user).toBeDefined();
      expect(result.user.confirmed).toBe(true);
      expect(result.accessToken).toBeDefined();
      expect(isJWT(result.accessToken)).toBe(true);
      expect(result.refreshToken).toBeDefined();
      expect(isJWT(result.refreshToken)).toBe(true);
    });

    it('should throw an error if the token is invalid', async () => {
      await expect(
        authService.confirmEmail({
          confirmationToken: token + '1',
        }),
      ).rejects.toThrow();
    });
  });

  describe('sign in', () => {
    it('should sign in an user by email', async () => {
      jest.spyOn(usersService, 'findOneByCredentials').mockResolvedValue({
        ...baseUser,
        password: await hash(baseUser.password, 10),
      });
      const result = await authService.signIn({
        email: baseUser.email,
        password: baseUser.password,
      });

      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(isJWT(result.accessToken)).toBe(true);
      expect(result.refreshToken).toBeDefined();
      expect(isJWT(result.refreshToken)).toBe(true);
    });

    it('should throw an unauthorized exception if the password is wrong', async () => {
      jest
        .spyOn(usersService, 'findOneByCredentials')
        .mockRejectedValueOnce(new Error());

      await expect(
        authService.signIn({
          email: baseUser.email,
          password: baseUser.password + 1,
        }),
      ).rejects.toThrow();
    });

    it('should throw an error if the user is not confirmed', async () => {
      jest.spyOn(usersService, 'findOneByCredentials').mockResolvedValueOnce({
        ...baseUser,
        password: await hash(baseUser.password, 10),
        confirmed: false,
      });

      await expect(
        authService.signIn({
          email: baseUser.email,
          password: baseUser.password,
        }),
      ).rejects.toThrow('Please confirm your email, a new email has been sent');
    });
  });

  describe('refresh token', () => {
    let token: string;

    it('should create a refresh token', async () => {
      token = await jwtService.generateToken(baseUser, TokenTypeEnum.REFRESH);
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should refresh the token', async () => {
      jest.spyOn(usersService, 'findOne').mockResolvedValue({
        ...baseUser,
        password: await hash(baseUser.password, 10),
      });

      const result = await authService.refreshTokenAccess(token);
      expect(result.accessToken).toBeDefined();
      expect(isJWT(result.accessToken)).toBe(true);
      expect(result.refreshToken).toBeDefined();
      expect(isJWT(result.refreshToken)).toBe(true);
    });

    it('should throw an error if the token is invalid', async () => {
      await expect(authService.refreshTokenAccess(token + '1')).rejects.toThrow(
        'Invalid token',
      );
    });
  });

  describe('logout', () => {
    it('should blacklist the token', async () => {
      const token = await jwtService.generateToken(
        baseUser,
        TokenTypeEnum.REFRESH,
      );
      const { id, tokenId } = await jwtService.verifyToken<IRefreshToken>(
        token,
        TokenTypeEnum.REFRESH,
      );

      expect(
        await cacheManager.get(`blacklist:${id}:${tokenId}`),
      ).toBeUndefined();
      await expect(authService.logout(token)).resolves.not.toThrow();
      expect(
        await cacheManager.get(`blacklist:${id}:${tokenId}`),
      ).toBeDefined();

      await expect(authService.refreshTokenAccess(token)).rejects.toThrow(
        'Invalid token',
      );
    });
  });

  describe('reset password email', () => {
    it('should send the reset password email', async () => {
      jest.spyOn(mailService, 'sendResetPasswordEmail').mockImplementation();
      jest.spyOn(usersService, 'findOneByEmail').mockResolvedValue(baseUser);

      await expect(
        authService.resetPasswordEmail({ email: baseUser.email }),
      ).resolves.not.toThrow();
      expect(mailService.sendResetPasswordEmail).toHaveBeenCalledTimes(1);
    });
  });

  const newPassword = faker.internet.password();
  describe('reset password', () => {
    let token: string;

    it('should create a reset password token', async () => {
      jest.spyOn(usersService, 'findOne').mockResolvedValue({
        ...baseUser,
        password: await hash(baseUser.password, 10),
      });

      token = await jwtService.generateToken(
        baseUser,
        TokenTypeEnum.RESET_PASSWORD,
      );
      expect(token).toBeDefined();
      expect(isJWT(token)).toBe(true);
    });

    it('should reset the password', async () => {
      jest.spyOn(usersService, 'resetPassword').mockResolvedValue({
        ...baseUser,
        password: await hash(newPassword, 10),
      });

      await expect(
        authService.resetPassword({
          resetToken: token,
          password: newPassword,
          newPassword,
        }),
      ).resolves.not.toThrow();
    });

    it('should throw an error if the token is invalid', async () => {
      await expect(
        authService.resetPassword({
          resetToken: token + '1',
          password: newPassword,
          newPassword,
        }),
      ).rejects.toThrow('Invalid token');
    });
  });

  const newPassword2 = faker.internet.password();
  describe('change password', () => {
    it('should change the password', async () => {
      jest.spyOn(usersService, 'findOne').mockResolvedValue(baseUser);
      jest.spyOn(usersService, 'resetPassword').mockResolvedValue({
        ...baseUser,
        password: await hash(newPassword2, 10),
      });

      const result = await authService.updatePassword(baseUser.id, {
        password: newPassword2,
      });
      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(isJWT(result.accessToken)).toBe(true);
      expect(result.refreshToken).toBeDefined();
      expect(isJWT(result.refreshToken)).toBe(true);
    });
  });

  afterAll(async () => {
    await module.close();
  });
});
