import { User } from '@prisma/client';
import { UserRoleEnums } from '../types/user-role.enum';
import { Exclude } from 'class-transformer';

export class UserResponseDto implements User {
  name: string;

  id: string;

  createdAt: Date;

  email: string;

  @Exclude()
  password: string;

  confirmed: boolean;

  role: UserRoleEnums;
}
