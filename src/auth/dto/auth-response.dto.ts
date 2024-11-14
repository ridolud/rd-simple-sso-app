import { Type } from 'class-transformer';
import { UserResponseDto } from 'src/users/dto/user-response.dto';

export class AuthResponseDto {
  @Type(() => UserResponseDto)
  public user: UserResponseDto;

  public accessToken: string;

  public refreshToken: string;
}
