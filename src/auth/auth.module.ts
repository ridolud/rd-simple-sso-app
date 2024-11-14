import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from 'src/jwt/jwt.module';
import { UsersModule } from 'src/users/users.module';
import { MailModule } from 'src/mail/mail.module';
import { AuthController } from './auth.controller';
import { ClientsModule } from 'src/clients/clients.module';

@Module({
  imports: [JwtModule, UsersModule, MailModule, ClientsModule],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
