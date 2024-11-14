import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ThrottlerModuleOptions,
  ThrottlerOptionsFactory,
} from '@nestjs/throttler';
import { RedisOptions } from 'ioredis';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';
import { IAppConfig } from './interfaces/app-config.interface';
import { ConfigKey, Environment } from './config';

@Injectable()
export class ThrottlerConfig implements ThrottlerOptionsFactory {
  private logger = new Logger(ThrottlerConfig.name);
  private appConfig: IAppConfig;

  constructor(private readonly configService: ConfigService) {
    this.appConfig = this.configService.get<IAppConfig>(ConfigKey.App);
  }

  createThrottlerOptions(): ThrottlerModuleOptions {
    this.logger.debug(this.configService.get<RedisOptions>(ConfigKey.Redis));
    return this.appConfig.env == Environment.test
      ? this.configService.get<ThrottlerModuleOptions>(ConfigKey.Throttler)
      : {
          ...this.configService.get<ThrottlerModuleOptions>(
            ConfigKey.Throttler,
          ),
          storage: new ThrottlerStorageRedisService(
            this.configService.get<RedisOptions>(ConfigKey.Redis),
          ),
        };
  }
}
