import { Controller, Get } from '@nestjs/common';
import { UsersService } from './users.service';
import { Public } from './decorators/public.decorator';

@Controller()
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('health')
  @Public()
  getHealth() {
    return {
      status: 'OK',
      service: 'Users Service',
      timestamp: new Date().toISOString(),
    };
  }
}