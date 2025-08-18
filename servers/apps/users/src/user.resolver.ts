import { BadRequestException, UseGuards } from '@nestjs/common';
import { User } from './entities/user.entities';
import { 
  RegisterResponse, 
  ActivationResponse, 
  LoginResponse, 
  LogoutResponse, 
  ForgotPasswordResponse, 
  ResetPasswordResponse 
} from './types/user.types';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { 
  RegisterDto, 
  ActivationDto, 
  LoginDto, 
  ForgotPasswordDto, 
  ResetPasswordDto 
} from './dto/user.dto';

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

    try {
      const { user, activationToken } = await this.usersService.register(registerDto);
      return {
        user: user as User, // Type assertion to fix the type error
        activationToken,
      };
    } catch (error) {
      return {
        error: {
          message: error.message,
        },
      };
    }
  }

  @Mutation(() => ActivationResponse)
  async activateUser(
    @Args('activationInput') activationDto: ActivationDto,
  ): Promise<ActivationResponse> {
    try {
      const { user } = await this.usersService.activateUser(activationDto);
      return { user: user as User };
    } catch (error) {
      return {
        error: {
          message: error.message,
        },
      };
    }
  }

  @Mutation(() => LoginResponse)
  async loginUser(
    @Args('loginInput') loginDto: LoginDto,
  ): Promise<LoginResponse> {
    try {
      const { user, accessToken, refreshToken } = await this.usersService.login(loginDto);
      return {
        user: user as User,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      return {
        error: {
          message: error.message,
        },
      };
    }
  }

  @Query(() => LoginResponse)
  async getLoggedInUser(@Context() context: { req: any }): Promise<LoginResponse> {
    try {
      const { user, accessToken, refreshToken } = await this.usersService.getLoggedInUser(context.req);
      return { user: user as User, accessToken, refreshToken };
    } catch (error) {
      return {
        error: {
          message: error.message,
        },
      };
    }
  }

  @Query(() => LogoutResponse)
  async logOutUser(@Context() context: { req: any }): Promise<LogoutResponse> {
    return await this.usersService.logout(context.req);
  }

  @Mutation(() => ForgotPasswordResponse)
  async forgotPassword(
    @Args('forgotPasswordInput') forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ForgotPasswordResponse> {
    try {
      const { message } = await this.usersService.forgotPassword(forgotPasswordDto);
      return { message };
    } catch (error) {
      return {
        message: 'An error occurred', // Provide required message field
        error: {
          message: error.message,
        },
      };
    }
  }

  @Mutation(() => ResetPasswordResponse)
  async resetPassword(
    @Args('resetPasswordInput') resetPasswordDto: ResetPasswordDto,
  ): Promise<ResetPasswordResponse> {
    try {
      const { user } = await this.usersService.resetPassword(resetPasswordDto);
      return { user: user as User };
    } catch (error) {
      return {
        error: {
          message: error.message,
        },
      };
    }
  }

  @Query(() => [User])
  async getUsers() {
    const users = await this.usersService.getUsers();
    return users.map(user => user as User);
  }
}