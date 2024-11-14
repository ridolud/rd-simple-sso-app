import { IsOptional, IsString, IsUrl } from 'class-validator';

export class ClientRequestDto {
  @IsString()
  clientId: string;

  @IsString()
  clientSecret: string;

  @IsOptional()
  @IsUrl({ require_tld: false })
  ridirect?: string;
}
