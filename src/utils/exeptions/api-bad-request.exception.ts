import {
  HttpException,
  HttpExceptionOptions,
  HttpStatus,
} from '@nestjs/common';

export class ApiBadRequestException extends HttpException {
  constructor(
    objectOrError?: string | object | any,
    descriptionOrOptions?: HttpExceptionOptions,
  ) {
    super(objectOrError, HttpStatus.BAD_REQUEST, descriptionOrOptions);
  }
}
