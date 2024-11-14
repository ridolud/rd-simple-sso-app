import { registerAs } from '@nestjs/config';
import { IJwtConfig } from './interfaces/jwt-config.interface';
import { RedisOptions } from 'ioredis';
import { parseRedisUrl } from 'parse-redis-url-simple';
import { ICookiesConfig } from './interfaces/cookies-config.interface';
import { IMailConfig } from './interfaces/email-config.interface';
import { IAppConfig } from './interfaces/app-config.interface';
import { ThrottlerModuleOptions } from '@nestjs/throttler';

export enum ConfigKey {
  App = 'APP',
  Jwt = 'JWT',
  Cookies = 'COOKIES',
  Redis = 'REDIS',
  Mail = 'MAIL',
  Throttler = 'THROTTLER',
}

export enum Environment {
  local = 'local',
  development = 'development',
  staging = 'staging',
  production = 'production',
  test = 'test',
}

const APPConfig = registerAs(ConfigKey.App, () => {
  const appConfig: IAppConfig = {
    env:
      Environment[process.env.NODE_ENV as keyof typeof Environment] ||
      'development',
    port: Number(process.env.APP_PORT),
    domain: process.env.APP_DOMAIN,
  };

  // Logger.debug('APPConfig', appConfig);
  return appConfig;
});

const JWTConfig = registerAs(ConfigKey.Jwt, () => {
  const jwtConfig: IJwtConfig = {
    access: {
      secret: process.env.JWT_ACCESS_SECRET ?? 'secret',
      time: Number(process.env.JWT_ACCESS_TIME ?? '60'),
    },
    client: {
      secret: process.env.JWT_CLIENT_SECRET ?? 'secret',
      time: Number(process.env.JWT_CLIENT_TIME ?? '60'),
    },
    confirmation: {
      secret: process.env.JWT_CONFIRMATION_SECRET ?? 'secret',
      time: Number(process.env.JWT_CONFIRMATION_TIME ?? '360'),
    },
    resetPassword: {
      secret: process.env.JWT_RESET_PASSWORD_SECRET ?? 'secret',
      time: Number(process.env.JWT_RESET_PASSWORD_TIME ?? '180'),
    },
    refresh: {
      secret: process.env.JWT_REFRESH_SECRET ?? 'secret',
      time: Number(process.env.JWT_REFRESH_TIME ?? '604800'),
    },
  };
  // Logger.debug('JWTConfig', jwtConfig);
  return jwtConfig;
});

const REDISConfig = registerAs(ConfigKey.Redis, () => {
  const redisConfig: RedisOptions = parseRedisUrl(process.env.REDIS_URL)[0] ?? {
    host: 'localhost',
  };
  return redisConfig;
});

const COOKIESConfig = registerAs(ConfigKey.Cookies, () => {
  const cookiesConfig: ICookiesConfig = {
    refreshId: process.env.COOKIE_REFRESH_ID ?? 'app-refresh-token',
    clientId: process.env.COOKIE_CLIENT_ID ?? 'app-client-token',
    secret: process.env.COOKIE_SECRET ?? 'secret',
    time: Number(process.env.COOKIE_SECRET_TIME ?? '604800'),
  };
  return cookiesConfig;
});

const MAILConfig = registerAs(ConfigKey.Mail, () => {
  const mailConfig: IMailConfig = {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
  };
  return mailConfig;
});

const THROTTLERConfig = registerAs(ConfigKey.Throttler, () => {
  const throttlerConfig: ThrottlerModuleOptions = [
    {
      ttl: parseInt(process.env.THROTTLE_TTL, 10),
      limit: parseInt(process.env.THROTTLE_LIMIT, 10),
    },
  ];

  return throttlerConfig;
});

export const configs = [
  APPConfig,
  JWTConfig,
  REDISConfig,
  COOKIESConfig,
  MAILConfig,
  THROTTLERConfig,
];
