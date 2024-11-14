import { IsString, MinLength } from 'class-validator';

export class PasswordDto {
  @IsString()
  @MinLength(8)
  password: string;
}
