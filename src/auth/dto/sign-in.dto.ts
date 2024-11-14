import { IsEmail, IsString, MinLength } from 'class-validator';
import { PasswordDto } from 'src/auth/dto/password.dto';

export class SignInDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;
}
