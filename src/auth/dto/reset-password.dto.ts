import { IsString, IsJWT, MinLength } from 'class-validator';
import { PasswordDto } from 'src/auth/dto/password.dto';

export class ResetPasswordDto {
  @IsString()
  @IsJWT()
  resetToken!: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @MinLength(8)
  newPassword: string;
}
