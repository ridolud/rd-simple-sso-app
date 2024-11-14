import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

@Catch(NotFoundException)
export class NotFoundViewExeptionFilter implements ExceptionFilter {
  private logger = new Logger(NotFoundViewExeptionFilter.name);

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: NotFoundException, host: ArgumentsHost) {
    this.logger.log(NotFoundViewExeptionFilter.name);

    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    const httpStatus =
      exception instanceof NotFoundException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    var responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      message: exception.message,
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
    };

    return httpAdapter.render(ctx.getResponse(), 'error', responseBody);
  }
}
