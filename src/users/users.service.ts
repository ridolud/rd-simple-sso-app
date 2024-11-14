import { BadRequestException, Injectable, Module } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UserFindDto } from './dto/user-find.dto';
import { Prisma, User } from '@prisma/client';
import { compare, hash } from 'bcrypt';
import defu from 'defu';
import { UserRoleEnums } from './types/user-role.enum';
import { UserUpdateDto } from './dto/user-update.dto';

@Injectable()
export class UsersService {
  constructor(private readonly prismaService: PrismaService) {}

  async find(options: UserFindDto): Promise<[number, User[]]> {
    options = defu(options, { take: 20, skip: 0, search: '' });

    const query: Prisma.UserWhereInput = {
      OR: [
        { email: { contains: options.search } },
        { name: { contains: options.search } },
      ],
    };

    return await this.prismaService.$transaction([
      this.prismaService.user.count({ where: query }),
      this.prismaService.user.findMany({
        where: query,
        skip: options.skip,
        take: options.take,
      }),
    ]);
  }

  async create(input: {
    name: string;
    email: string;
    password: string;
  }): Promise<User> {
    return await this.prismaService.user.create({
      data: {
        name: input.name.toLowerCase(),
        email: input.email.toLowerCase(),
        password: await hash(input.password, 10),
        role: UserRoleEnums.USER,
      },
    });
  }

  async findOne(id: string): Promise<User> {
    return await this.prismaService.user.findUniqueOrThrow({
      where: { id },
    });
  }

  async findOneByEmail(email: string): Promise<User> {
    const user = await this.prismaService.user.findFirstOrThrow({
      where: { email: email.toLowerCase() },
    });
    return user;
  }

  async isRegistered(email: string): Promise<User> {
    const user = await this.prismaService.user.findFirst({
      where: { email: email.toLowerCase() },
    });
    return user;
  }

  async update(id: string, input: UserUpdateDto): Promise<User> {
    return await this.prismaService.user.update({
      where: { id },
      data: {
        name: input.name?.toLowerCase(),
        email: input.email?.toLowerCase(),
        role: input.role,
      },
    });
  }

  async delete(id: string) {
    return await this.prismaService.user.delete({
      where: { id },
    });
  }

  async confirmEmail(id: string): Promise<User> {
    return await this.prismaService.user.update({
      where: { id },
      data: { confirmed: true },
    });
  }

  async updateEmail(id: string, email: string): Promise<User> {
    return await this.prismaService.user.update({
      where: { id },
      data: { confirmed: false, email: email.toLowerCase() },
    });
  }

  async resetPassword(id: string, password: string): Promise<User> {
    return await this.prismaService.user.update({
      where: { id },
      data: { password: await hash(password, 10) },
    });
  }

  async findOneByCredentials(
    idOrEmail: string,
    password: string,
  ): Promise<User> {
    const user = await this.prismaService.user.findFirst({
      where: {
        OR: [{ id: idOrEmail }, { email: idOrEmail.toLowerCase() }],
      },
    });
    if (!user || !(await compare(password, user.password)))
      throw new BadRequestException('Credential Invalid');

    return user;
  }
}
