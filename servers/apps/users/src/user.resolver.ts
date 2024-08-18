import { BadRequestException } from '@nestjs/common';
import { User } from './entities/user.entities';
import { RegisterResponse } from './types/user.types';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { RegisterDto } from './dto/user.dto';

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly usersService: UsersService) {}

  @Mutation(() => RegisterResponse)
  async register(
    @Args('registerInput') registerDto: RegisterDto,
  ): Promise<RegisterResponse> {
    if (!registerDto.name || !registerDto.email || !registerDto.password) {
      throw new BadRequestException('Please fill in all fields');
    }
    const user = await this.usersService.register(registerDto);
    return { user };
  }
  
  @Query(() => [User])
  async getUsers() {
    return this.usersService.getUsers();
  }
}
