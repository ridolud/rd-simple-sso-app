import { IsNumber, IsNumberString, IsOptional } from 'class-validator';

export class PaginationDto {
  @IsNumberString()
  @IsOptional()
  skip?: number;

  @IsNumberString()
  @IsOptional()
  take?: number;
}
