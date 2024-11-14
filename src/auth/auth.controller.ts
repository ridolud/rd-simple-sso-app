import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Query,
  Render,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { query, Request, Response } from 'express';
import { Origin } from './decorators/origin.decorator';
import { SignUpDto } from './dto/sign-up.dto';
import { MailService } from 'src/mail/mail.service';
import { SignInDto } from './dto/sign-in.dto';
import { ClientGuard } from 'src/clients/guards/client.guard';
import { ClientRequestDto } from 'src/clients/dto/client-request.dto';
import { ClientsService } from 'src/clients/clients.service';
import { ClientId } from 'src/clients/decorators/cient-id.decorator';
import { ClientRedirectUrl } from 'src/clients/decorators/cient-redirect-url.decorator';
import { UserId } from './decorators/user-id.decorator';
import { UsersService } from 'src/users/users.service';
import { plainToInstance } from 'class-transformer';
import { UserResponseDto } from 'src/users/dto/user-response.dto';
import { AuthGuard } from './guards/auth.guard';
import { Public } from './decorators/public.docorator';
import { ConfirmEmailDto } from './dto/confirm-email.dto';
import { EmailDto } from './dto/email.dto';
import { IsString } from 'class-validator';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly clientsServices: ClientsService,
  ) {}

  @Get()
  @Public()
  @UseGuards(AuthGuard)
  async confirm(
    @Res() res: Response,
    @Origin() origin: string,
    @Query() query: ClientRequestDto,
    @UserId() userId: string | undefined,
  ) {
    // validating client credentials request
    const client = await this.clientsServices.findOneByCredentials(
      query.clientId,
      query.clientSecret,
    );
    if (!client) throw new UnauthorizedException('Invalid client credentials');

    // validating redirect(callback)'s url
    let redirectUrl = query.ridirect ?? client.redirectUrls[0].url;
    if (
      query.ridirect &&
      !client.redirectUrls.map((i) => i.url).includes(redirectUrl)
    )
      throw new UnauthorizedException('Redirect url not register yet!');

    // save client identity and redirect url to a token then save to cookie
    const clientToken = await this.clientsServices.generateToken(
      client,
      origin,
      redirectUrl,
    );

    // if already logged, user will be redirect to callback
    if (userId) {
      const user = await this.usersService.findOne(userId);
      const [accessToken] = await this.authService.generateAuthTokens(user);
      return res
        .status(HttpStatus.MOVED_PERMANENTLY)
        .redirect(redirectUrl + `?token=${accessToken}`);
    }

    return this.clientsServices
      .saveTokenCookie(res, clientToken)
      .redirect('/auth/signin');
  }

  @Get('/signin')
  @Render('signin')
  @UseGuards(ClientGuard)
  login(@Res() res: Response, @ClientRedirectUrl() redirectUrl: string) {
    res.setHeader(
      'Content-Security-Policy',
      `form-action 'self' ${redirectUrl}`,
    );
    return {};
  }

  @Post('/signin')
  @UseGuards(ClientGuard)
  async doLogin(
    @Res() res: Response,
    @Body() input: SignInDto,
    @ClientRedirectUrl() redirectUrl: string,
  ) {
    const { accessToken, refreshToken } = await this.authService.signIn(input);
    this.authService
      .saveRefreshCookie(res, refreshToken)
      .redirect(redirectUrl + `?token=${accessToken}`);
  }

  @Get('/signup')
  @Render('signup')
  @UseGuards(ClientGuard)
  signUp(@Res() res: Response) {
    return {};
  }

  @Post('/signup')
  @UseGuards(ClientGuard)
  async doSignUp(@Res() res: Response, @Body() input: SignUpDto) {
    await this.authService.signUp(input);
    return res.status(HttpStatus.MOVED_PERMANENTLY).redirect('/auth/signin');
  }

  @Get('/me')
  @UseGuards(AuthGuard)
  async getProfile(@UserId() userId: string) {
    const user = await this.usersService.findOne(userId);
    return plainToInstance(UserResponseDto, user);
  }

  @Post('/confirm-email')
  @UseGuards(ClientGuard, AuthGuard)
  async confirmEmail(
    @Res() res: Response,
    @Origin() origin: string,
    @Body() input: ConfirmEmailDto,
    @ClientRedirectUrl() redirectUrl: string,
  ) {
    const { refreshToken, accessToken } = await this.authService.confirmEmail(
      input,
      origin,
    );
    this.authService
      .saveRefreshCookie(res, refreshToken)
      .redirect(redirectUrl + `?token=${accessToken}`);
  }

  @Get('/forgot-password')
  @UseGuards(ClientGuard)
  @Render('forgot-password')
  async forgotPassword() {
    return {};
  }

  @Post('/forgot-password')
  @UseGuards(ClientGuard)
  async doForgotPassword(
    @Res() res: Response,
    @Body() input: EmailDto,
    @Origin() origin?: string,
  ) {
    await this.authService.resetPasswordEmail(input, origin);
    return res.status(HttpStatus.MOVED_PERMANENTLY).redirect('/auth/signin');
  }

  @Get('/reset-password')
  @UseGuards(ClientGuard)
  @Render('reset-password')
  async resetPassword(
    @Query('token') token: string,
    @Origin() origin?: string,
  ) {
    await this.authService.verifyResetPasswordToken(token, origin);
    return { token };
  }

  @Post('/reset-password')
  @UseGuards(ClientGuard)
  async doResetPassword(@Res() res: Response, @Body() input: ResetPasswordDto) {
    await this.authService.resetPassword(input);
    return res.status(HttpStatus.MOVED_PERMANENTLY).redirect('/auth/signin');
  }
}
