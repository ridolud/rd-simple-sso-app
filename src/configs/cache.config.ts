import { CacheModuleOptions, CacheOptionsFactory } from '@nestjs/cache-manager';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { redisStore } from 'cache-manager-ioredis-yet';
import { ICookiesConfig } from './interfaces/cookies-config.interface';
import { RedisOptions } from 'ioredis';
import { ConfigKey, Environment } from './config';
import { IAppConfig } from './interfaces/app-config.interface';

@Injectable()
export class CacheConfig implements CacheOptionsFactory {
  private logger = new Logger(CacheConfig.name);

  private cookiesConfig: ICookiesConfig;
  private redisConfig: RedisOptions;
  private appConfig: IAppConfig;

  constructor(private readonly configService: ConfigService) {
    this.appConfig = this.configService.get<IAppConfig>(ConfigKey.App);
    this.cookiesConfig = this.configService.get<ICookiesConfig>(
      ConfigKey.Cookies,
    );
    this.redisConfig = this.configService.get<RedisOptions>(ConfigKey.Redis);
  }

  async createCacheOptions(): Promise<CacheModuleOptions | any> {
    return this.appConfig.env == Environment.test
      ? {
          ttl: this.cookiesConfig.time,
        }
      : {
          store: await redisStore({
            ...this.redisConfig,
            ttl: this.cookiesConfig.time,
          }),
        };
  }
}
