import { Global, Module } from '@nestjs/common';
import { ConfigsModule } from './configs/config.module';
import { UsersModule } from './users/users.module';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule } from '@nestjs/config';
import { CacheConfig } from './configs/cache.config';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerConfig } from './configs/throttler.config';
import { AuthModule } from './auth/auth.module';
import { APP_FILTER } from '@nestjs/core';
import { NotFoundViewExeptionFilter } from './utils/filter/not-found-view-exeption.filter';
import { BadGatewayViewExeptionFilter } from './utils/filter/bad-gatway-view-exeption.filter';
import { BadRequestViewExeptionFilter } from './utils/filter/bad-request-view-exeption.filter';
import { ClientsModule } from './clients/clients.module';

@Module({
  imports: [
    ConfigsModule,
    CacheModule.registerAsync({
      isGlobal: true,
      imports: [ConfigsModule],
      useClass: CacheConfig,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      useClass: ThrottlerConfig,
    }),
    UsersModule,
    AuthModule,
    ClientsModule,
  ],
  providers: [
    { provide: APP_FILTER, useClass: NotFoundViewExeptionFilter },
    { provide: APP_FILTER, useClass: BadGatewayViewExeptionFilter },
    { provide: APP_FILTER, useClass: BadRequestViewExeptionFilter },
  ],
})
export class AppModule {}
