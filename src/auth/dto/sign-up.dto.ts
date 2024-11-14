import { IsEmail, IsString, Matches, MinLength } from 'class-validator';
import { NAME_REGEX } from 'src/utils/consts/regexs';

export class SignUpDto {
  @IsEmail()
  email: string;

  @IsString()
  @Matches(NAME_REGEX)
  name: string;

  @IsString()
  @MinLength(8)
  password: string;
}
