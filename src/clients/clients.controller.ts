import { Body, Controller, Delete, Get, Param, Post } from '@nestjs/common';
import { ClientsService } from './clients.service';
import { ClientCreateDto } from './dto/client-create.dto';
import { ClientUpdateDto } from './dto/client-update.dto';

@Controller('clients')
export class ClientsController {
  constructor(private readonly clientsService: ClientsService) {}

  @Post()
  async generate(@Body() input: ClientCreateDto) {
    return await this.clientsService.generate(input.redirectUrls);
  }

  @Post('/:id')
  async update(@Body() input: ClientUpdateDto, @Param('id') id: string) {
    return await this.clientsService.updateRedirectUrl(id, input.redirectUrls);
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    return await this.clientsService.findOne(id);
  }

  @Delete('/:id')
  async remove(@Param('id') id: string) {
    return await this.clientsService.remove(id);
  }
}
