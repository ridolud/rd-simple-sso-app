import {
  ArgumentsHost,
  BadGatewayException,
  BadRequestException,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { Request, Response } from 'express';
import { existsSync } from 'fs';
import { join } from 'path';

@Catch(BadRequestException)
export class BadRequestViewExeptionFilter implements ExceptionFilter {
  private logger = new Logger(BadRequestViewExeptionFilter.name);

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: BadRequestException, host: ArgumentsHost) {
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    const httpStatus =
      exception instanceof BadRequestException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const data: any = exception.getResponse();
    const path: string = httpAdapter.getRequestUrl(ctx.getRequest());

    const responseBody = {
      title: 'Bad Request',
      statusCode: httpStatus,
      path,
      message: Array.isArray(data?.message)
        ? data.message[0]
        : exception.message,
    };

    const paths = path.split('/');
    var viewName = paths[paths.length - 1] ?? 'error';

    if (!existsSync(join(__dirname, '../../../views', `${viewName}.ejs`))) {
      httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
    } else {
      httpAdapter.render(ctx.getResponse(), viewName, responseBody);
    }
  }
}
