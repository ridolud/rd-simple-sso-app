import { IsString, MinLength, IsEmail } from 'class-validator';

export class UserCreateDto {
  @IsString()
  @MinLength(1)
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}
