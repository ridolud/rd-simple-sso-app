import { IsArray, IsUrl } from 'class-validator';

export class ClientCreateDto {
  @IsArray()
  @IsUrl({ require_tld: false }, { each: true })
  redirectUrls: string[];
}
