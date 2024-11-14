import { Injectable, Logger, LoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createTransport, Transporter } from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { IMailConfig } from 'src/configs/interfaces/email-config.interface';
import { ConfigKey } from 'src/configs/config';
import { IAppConfig } from 'src/configs/interfaces/app-config.interface';
import * as ejs from 'ejs';
import { IMailDataTemplate } from './interfaces/template-data.interface';

@Injectable()
export class MailService {
  private readonly loggerService: LoggerService = new Logger(MailService.name);
  private readonly transport: Transporter<SMTPTransport.SentMessageInfo>;
  private readonly email: string;
  private readonly domain: string;

  constructor(private readonly configService: ConfigService) {
    const emailConfig = this.configService.get<IMailConfig>(ConfigKey.Mail);
    const appConfig = this.configService.get<IAppConfig>(ConfigKey.App);

    this.transport = createTransport(emailConfig);
    this.email = `"SSO-APP" <${emailConfig.auth.user}>`;
    this.domain = appConfig.domain;

    this.transport.verify((err) => {
      if (err) this.loggerService.error('connection fail!');
    });
  }

  private parseTemplate(templateName: string, data: IMailDataTemplate): string {
    const templateText = readFileSync(
      join(__dirname, 'templates', templateName),
      'utf-8',
    );
    return ejs.render(templateText, data);
  }

  public sendConfirmationEmail(user: User, token: string) {
    const { email, name } = user;
    const subject = 'Confirm your email';
    const html = this.parseTemplate('confirmation.ejs', {
      name,
      link: `https://${this.domain}/auth/confirm/${token}`,
    });
    this.sendEmail(email, subject, html, 'A new confirmation email was sent.');
  }

  public sendResetPasswordEmail(user: User, token: string) {
    const { email, name } = user;
    const subject = 'Reset your password';
    const html = this.parseTemplate('reset-password.ejs', {
      name,
      link: `https://${this.domain}/auth/reset-password?token=${token}`,
    });
    this.sendEmail(
      email,
      subject,
      html,
      'A new reset password email was sent.',
    );
  }

  public sendEmail(
    to: string,
    subject: string,
    html: string,
    log?: string,
  ): void {
    this.transport
      .sendMail({
        from: this.email,
        to,
        subject,
        html,
      })
      .then(() => this.loggerService.log(log ?? 'A new email was sent.'))
      .catch((error) => this.loggerService.error(error));
  }
}
