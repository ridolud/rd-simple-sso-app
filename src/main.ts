import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import * as expressLayouts from 'express-ejs-layouts';
import { BadRequestException, ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ICookiesConfig } from './configs/interfaces/cookies-config.interface';
import { ConfigKey, Environment } from './configs/config';
import { IAppConfig } from './configs/interfaces/app-config.interface';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  const appConfig = configService.get<IAppConfig>(ConfigKey.App);
  const cookiesConfig = configService.get<ICookiesConfig>(ConfigKey.Cookies);

  // views
  app.useStaticAssets(join(__dirname, '..', 'public'));
  app.setBaseViewsDir(join(__dirname, '..', 'views'));
  app.use(expressLayouts);
  app.setViewEngine('ejs');
  app.set('layout', 'layouts/default');

  app.use(
    helmet({
      // contentSecurityPolicy: {
      //   useDefaults: true,
      //   directives: {
      //     defaultSrc: ["'self'"],
      //     formAction: ["'self'", 'http://localhost:8000/callback'],
      //   },
      // },
    }),
  );
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      forbidNonWhitelisted: true,
      whitelist: true,
    }),
  );
  app.enableCors();
  app.use(cookieParser(cookiesConfig.secret));

  await app.listen(
    appConfig.port,
    appConfig.env == Environment.production ? '127.0.0.1' : '0.0.0.0',
  );
}
bootstrap();
