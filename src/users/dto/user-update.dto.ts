import { PartialType } from '@nestjs/mapped-types';
import { UserCreateDto } from './user-create.dto';
import { IsEnum, IsOptional, IsString } from 'class-validator';
import { UserRoleEnums } from '../types/user-role.enum';

export class UserUpdateDto extends PartialType(UserCreateDto) {
  @IsOptional()
  @IsEnum(UserRoleEnums)
  role: UserRoleEnums;
}
