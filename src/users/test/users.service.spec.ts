import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from '../users.service';
import { ConfigsModule } from 'src/configs/config.module';
import { PrismaModule } from 'src/prisma/prisma.module';
import { User } from '@prisma/client';
import { randomUUID } from 'crypto';
import { faker } from '@faker-js/faker';
import { UserRoleEnums } from '../types/user-role.enum';
import { PrismaService } from 'src/prisma/prisma.service';
import { compare, hash } from 'bcrypt';

describe('UsersService', () => {
  let module: TestingModule;
  let service: UsersService;
  let prismaService: PrismaService;
  var dummyUser: User;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [ConfigsModule, PrismaModule],
      providers: [UsersService],
    }).compile();

    service = module.get<UsersService>(UsersService);
    prismaService = module.get<PrismaService>(PrismaService);
    dummyUser = {
      id: randomUUID(),
      name: faker.internet.displayName(),
      password: faker.internet.password(),
      email: faker.internet.email(),
      createdAt: new Date(),
      confirmed: true,
      role: UserRoleEnums.USER,
    };
  });

  describe('create', () => {
    it('should create a user', async () => {
      const user = await service.create(dummyUser);
      dummyUser.id = user.id;

      expect(user).toBeDefined();
    });

    it('should throw a conflict exception', async () => {
      await expect(service.create(dummyUser)).rejects.toThrow();
    });
  });

  describe('read', () => {
    it('should find users', async () => {
      const [total, records] = await service.find({});
      expect(total).toBeGreaterThanOrEqual(1);
      expect(records).toBeDefined();
    });

    it('should find a user by id', async () => {
      const user = await service.findOne(dummyUser.id);
      expect(user).toBeDefined();
    });

    it('should find a user by email', async () => {
      const user = await service.findOneByEmail(dummyUser.email);
      expect(user).toBeDefined();
    });

    it('should find a user by credentials', async () => {
      const user = await service.findOneByCredentials(
        dummyUser.email,
        dummyUser.password,
      );
      expect(user).toBeDefined();
    });
  });

  describe('update', () => {
    it('should update a user', async () => {
      const name = faker.internet.displayName();
      const user = await service.update(dummyUser.id, {
        name,
        role: UserRoleEnums.USER,
      });
      expect(user.name).toBeDefined();
    });

    it('should reset a user password', async () => {
      const user = await service.resetPassword(dummyUser.id, 'new-password');
      expect(user).toBeDefined();
      expect(await compare('new-password', user.password)).toBe(true);
    });

    describe('email', () => {
      it('should update a user email', async () => {
        const newEmail = faker.internet.email();

        const user = await service.updateEmail(dummyUser.id, newEmail);
        expect(user.email).toEqual(newEmail.toLowerCase());
      });

      //   it('should throw a conflict exception', async () => {
      //     await expect(
      //       service.updateEmail(dummyUser1.id, dummyUser2.email),
      //     ).rejects.toThrow();
      //   });
    });
  });

  describe('delete', () => {
    it('should delete a user', async () => {
      const user = await service.delete(dummyUser.id);
      expect(user).toBeDefined();

      await expect(service.findOne(dummyUser.id)).rejects.toThrow();
    });
  });

  afterAll(async () => {
    try {
      const user = await prismaService.user.findFirst({
        where: { id: dummyUser.id },
      });

      if (user)
        await prismaService.user.delete({ where: { id: dummyUser.id } });
    } catch (err) {
      console.warn(err);
    }

    await module.close();
  });
});
