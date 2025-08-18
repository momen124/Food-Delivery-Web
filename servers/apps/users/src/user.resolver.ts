import { 
  BadRequestException, 
  UseGuards, 
  UsePipes, 
  ValidationPipe,
  Logger,
  InternalServerErrorException
} from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import {
  ActivationResponse,
  ForgotPasswordResponse,
  LoginResponse,
  LogoutResponse, // Fixed typo
  RegisterResponse,
  ResetPasswordResponse,
} from './types/user.types';
import {
  ActivationDto,
  ForgotPasswordDto,
  RegisterDto,
  ResetPasswordDto,
  LoginDto,
} from './dto/user.dto';
import { Response, Request } from 'express';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entities';
import { UsersService } from './users.service';

@Resolver('User')
@UsePipes(new ValidationPipe({ 
  transform: true,
  whitelist: true,
  forbidNonWhitelisted: true,
  exceptionFactory: (errors) => {
    const messages = errors.map(error => 
      Object.values(error.constraints || {}).join(', ')
    ).join('; ');
    return new BadRequestException(`Validation failed: ${messages}`);
  }
}))
export class UsersResolver {
  private readonly logger = new Logger(UsersResolver.name);

  constructor(private readonly userService: UsersService) {}

  @Mutation(() => RegisterResponse)
  async register(
    @Args('registerDto') registerDto: RegisterDto,
    @Context() context: { res: Response },
  ): Promise<RegisterResponse> {
    try {
      // Additional validation
      if (!registerDto.name?.trim() || !registerDto.email?.trim() || !registerDto.password?.trim()) {
        throw new BadRequestException('Please fill in all required fields');
      }

      this.logger.log(`Registration request for: ${registerDto.email}`);

      const result = await this.userService.register(registerDto, context.res);

      return { 
        activationToken: result.activation_token,
        user: null, // Don't return user data until activated
        error: null 
      };

    } catch (error) {
      this.logger.error('Registration resolver error', error.stack);
      
      return {
        user: null,
        activationToken: null,
        error: {
          message: error.message || 'Registration failed',
          code: error.status?.toString() || 'REGISTRATION_ERROR'
        }
      };
    }
  }

  @Mutation(() => ActivationResponse)
  async activateUser(
    @Args('activationDto') activationDto: ActivationDto,
    @Context() context: { res: Response },
  ): Promise<ActivationResponse> {
    try {
      this.logger.log('User activation request');

      const result = await this.userService.activateUser(activationDto, context.res);

      return {
        user: result.user,
        error: null
      };

    } catch (error) {
      this.logger.error('Activation resolver error', error.stack);
      
      return {
        user: null,
        error: {
          message: error.message || 'Account activation failed',
          code: error.status?.toString() || 'ACTIVATION_ERROR'
        }
      };
    }
  }

  @Mutation(() => LoginResponse)
  async login(
    @Args('loginDto') loginDto: LoginDto,
  ): Promise<LoginResponse> {
    try {
      // Validate input
      if (!loginDto.email?.trim() || !loginDto.password?.trim()) {
        throw new BadRequestException('Email and password are required');
      }

      this.logger.log(`Login request for: ${loginDto.email}`);

      const result = await this.userService.login(loginDto);

      return result;

    } catch (error) {
      this.logger.error('Login resolver error', error.stack);
      
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: error.message || 'Login failed',
          code: error.status?.toString() || 'LOGIN_ERROR'
        }
      };
    }
  }

  @Query(() => LoginResponse)
  @UseGuards(AuthGuard)
  async getLoggedInUser(@Context() context: { req: Request }): Promise<LoginResponse> {
    try {
      this.logger.log('Get logged in user request');

      const result = await this.userService.getLoggedInUser(context.req);

      return {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        error: null
      };

    } catch (error) {
      this.logger.error('Get logged in user resolver error', error.stack);
      
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: error.message || 'Failed to get user information',
          code: error.status?.toString() || 'GET_USER_ERROR'
        }
      };
    }
  }

  @Mutation(() => ForgotPasswordResponse)
  async forgotPassword(
    @Args('forgotPasswordDto') forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ForgotPasswordResponse> {
    try {
      if (!forgotPasswordDto.email?.trim()) {
        throw new BadRequestException('Email is required');
      }

      this.logger.log(`Forgot password request for: ${forgotPasswordDto.email}`);

      const result = await this.userService.forgotPassword(forgotPasswordDto);

      return {
        message: result.message,
        error: null
      };

    } catch (error) {
      this.logger.error('Forgot password resolver error', error.stack);
      
      return {
        message: null,
        error: {
          message: error.message || 'Password reset request failed',
          code: error.status?.toString() || 'FORGOT_PASSWORD_ERROR'
        }
      };
    }
  }

  @Mutation(() => ResetPasswordResponse)
  async resetPassword(
    @Args('resetPasswordDto') resetPasswordDto: ResetPasswordDto,
  ): Promise<ResetPasswordResponse> {
    try {
      if (!resetPasswordDto.password?.trim() || !resetPasswordDto.activationToken?.trim()) {
        throw new BadRequestException('Password and activation token are required');
      }

      this.logger.log('Password reset request');

      const result = await this.userService.resetPassword(resetPasswordDto);

      return {
        user: result.user,
        error: null
      };

    } catch (error) {
      this.logger.error('Reset password resolver error', error.stack);
      
      return {
        user: null,
        error: {
          message: error.message || 'Password reset failed',
          code: error.status?.toString() || 'RESET_PASSWORD_ERROR'
        }
      };
    }
  }

  @Query(() => LogoutResponse)
  @UseGuards(AuthGuard)
  async logOutUser(@Context() context: { req: Request }): Promise<LogoutResponse> {
    try {
      this.logger.log('Logout request');

      const result = await this.userService.logout(context.req);

      return {
        message: result.message
      };

    } catch (error) {
      this.logger.error('Logout resolver error', error.stack);
      
      return {
        message: 'Logout failed'
      };
    }
  }

  @Query(() => [User])
  @UseGuards(AuthGuard) // Protect this endpoint
  async getUsers(): Promise<User[]> {
    try {
      this.logger.log('Get all users request');

      const users = await this.userService.getUsers();
      
      return users;

    } catch (error) {
      this.logger.error('Get users resolver error', error.stack);
      throw new InternalServerErrorException('Failed to fetch users');
    }
  }
}