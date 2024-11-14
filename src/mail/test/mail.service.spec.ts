import { faker } from '@faker-js/faker';
import { ConfigModule } from '@nestjs/config';
import { TestingModule, Test } from '@nestjs/testing';
import { User } from '@prisma/client';
import { randomUUID } from 'crypto';
import { ConfigsModule } from 'src/configs/config.module';
import { MailService } from 'src/mail/mail.service';
import { UserRoleEnums } from 'src/users/types/user-role.enum';

describe('MailerService', () => {
  let service: MailService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [ConfigsModule],
      providers: [MailService],
    }).compile();

    service = module.get<MailService>(MailService);
    jest
      .spyOn(service, 'sendEmail')
      .mockImplementation((_, __, html: string, log?: string) => {
        console.log('html', html);
        if (log) {
          console.log(log);
        }
      });
  });

  const dummyUser1: User = {
    id: randomUUID(),
    name: faker.internet.displayName(),
    password: faker.internet.password(),
    email: faker.internet.email(),
    createdAt: new Date(),
    confirmed: true,
    role: UserRoleEnums.USER,
  };

  describe('sendEmail', () => {
    it('send confirmation email', async () => {
      service.sendConfirmationEmail(dummyUser1, 'token');
      expect(service.sendEmail).toHaveBeenCalled();
    });

    it('send reset password email', async () => {
      service.sendResetPasswordEmail(dummyUser1, 'token');
      expect(service.sendEmail).toHaveBeenCalled();
    });
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
