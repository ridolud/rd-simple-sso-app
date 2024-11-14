import { Module } from '@nestjs/common';
import { PrismaModule } from 'src/prisma/prisma.module';
import { ClientsService } from './clients.service';
import { ClientsController } from './clients.controller';
import { JwtModule } from 'src/jwt/jwt.module';

@Module({
  imports: [PrismaModule, JwtModule],
  //   controllers: [ClientsController],
  providers: [ClientsService],
  exports: [ClientsService],
})
export class ClientsModule {}
