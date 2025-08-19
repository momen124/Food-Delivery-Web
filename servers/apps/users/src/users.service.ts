import { 
  BadRequestException, 
  Injectable, 
  InternalServerErrorException,
  UnauthorizedException,
  ConflictException,
  NotFoundException,
  Logger,
  OnModuleInit
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import {
  ActivationDto,
  ForgotPasswordDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
} from './dto/user.dto';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/sendToken';
import { User } from '@prisma/client';
import { PrismaService } from "../../../prisma/prisma.service";
import { Prisma } from '@prisma/client';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number?: string;
}

@Injectable()
export class UsersService implements OnModuleInit {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  // Initialize service with config validation
  async onModuleInit() {
    try {
      this.validateRequiredConfig();
      this.logger.log('UsersService initialized successfully');
    } catch (error) {
      this.logger.error('UsersService initialization failed', error.stack);
      throw error;
    }
  }

  // register user service
  async register(registerDto: RegisterDto, response: Response) {
    try {
      const { name, email, password, phone_number } = registerDto;

      this.logger.log(`Registration attempt for email: ${email}`);

      // Check if user already exists with this email
      const isEmailExist = await this.prisma.user.findUnique({
        where: { email },
      });

      if (isEmailExist) {
        throw new ConflictException('User already exists with this email!');
      }

      // Check phone number uniqueness if provided
      if (phone_number) {
        const isPhoneExist = await this.prisma.user.findFirst({
          where: {
            phone_number: phone_number,
            NOT: { phone_number: null }
          },
        });

        if (isPhoneExist) {
          throw new ConflictException('User already exists with this phone number!');
        }
      }

      // Hash password with increased salt rounds for security
      const hashedPassword = await bcrypt.hash(password, 12);

      const user: UserData = {
        name,
        email,
        password: hashedPassword,
        phone_number,
      };

      // Create activation token
      const activationToken = await this.createActivationToken(user);
      const activationCode = activationToken.activationCode;
      const activation_token = activationToken.token;

      // Send activation email only if not in test environment
      if (this.configService.get('NODE_ENV') !== 'test') {
        try {
          await this.emailService.sendMail({
            email,
            subject: 'Activate your account!',
            template: './activation-mail',
            name,
            activationCode,
          });
          this.logger.log(`Activation email sent to: ${email}`);
        } catch (emailError) {
          this.logger.warn(`Failed to send activation email to ${email}:`, emailError.message);
          // In production, you might want to queue this for retry
          // For now, we'll continue without failing the registration
        }
      } else {
        this.logger.log(`Skipped sending activation email in test environment for: ${email}`);
      }

      return { activation_token, response };

    } catch (error) {
      this.logger.error(`Registration failed for email: ${registerDto.email}`, error.stack);
      
      if (error instanceof ConflictException || error instanceof BadRequestException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Registration failed. Please try again later.');
    }
  }

  // create activation token
  async createActivationToken(user: UserData) {
    try {
      const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

      const token = this.jwtService.sign(
        {
          user,
          activationCode,
        },
        {
          secret: this.configService.get<string>('ACTIVATION_SECRET'),
          expiresIn: '5m',
        },
      );

      return { token, activationCode };
    } catch (error) {
      this.logger.error('Failed to create activation token', error.stack);
      throw new InternalServerErrorException('Failed to create activation token');
    }
  }

  // activation user
  async activateUser(activationDto: ActivationDto, response: Response) {
    try {
      const { activationToken, activationCode } = activationDto;

      this.logger.log('User activation attempt');

      // Verify activation token
      let newUser: { user: UserData; activationCode: string };
      
      try {
        newUser = this.jwtService.verify(activationToken, {
          secret: this.configService.get<string>('ACTIVATION_SECRET'),
        } as JwtVerifyOptions) as { user: UserData; activationCode: string };
      } catch (jwtError) {
        this.logger.warn('Invalid or expired activation token');
        throw new BadRequestException('Invalid or expired activation token');
      }

      // Verify activation code
      if (newUser.activationCode !== activationCode) {
        this.logger.warn('Invalid activation code provided');
        throw new BadRequestException('Invalid activation code');
      }

      const { name, email, password, phone_number } = newUser.user;

      // Double-check if user already exists
      const existUser = await this.prisma.user.findUnique({
        where: { email },
      });

      if (existUser) {
        throw new ConflictException('User already exists with this email!');
      }

      // Create user in database
      const user = await this.prisma.user.create({
        data: {
          name,
          email,
          password,
          phone_number: phone_number || null,
        },
      });

      this.logger.log(`User activated successfully: ${email}`);

      return { user, response };

    } catch (error) {
      this.logger.error('User activation failed', error.stack);
      
      if (error instanceof BadRequestException || error instanceof ConflictException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Account activation failed. Please try again.');
    }
  }

  // Login service
  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;

      this.logger.log(`Login attempt for email: ${email}`);

      // Find user by email
      const user = await this.prisma.user.findUnique({
        where: { email },
        include: { avatar: true }
      });

      if (!user) {
        this.logger.warn(`Login failed - user not found: ${email}`);
        throw new UnauthorizedException('Invalid email or password');
      }

      // Verify password
      const isPasswordValid = await this.comparePassword(password, user.password);
      
      if (!isPasswordValid) {
        this.logger.warn(`Login failed - invalid password for: ${email}`);
        throw new UnauthorizedException('Invalid email or password');
      }

      // Generate tokens
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      const tokens = tokenSender.sendToken(user);

      this.logger.log(`User logged in successfully: ${email}`);

      return tokens;

    } catch (error) {
      this.logger.error(`Login failed for email: ${loginDto.email}`, error.stack);
      
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Login failed. Please try again later.');
    }
  }

  // compare with hashed password
  async comparePassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      this.logger.error('Password comparison failed', error.stack);
      throw new InternalServerErrorException('Authentication failed');
    }
  }

  // generate forgot password link
  async generateForgotPasswordLink(user: User) {
    try {
      const forgotPasswordToken = this.jwtService.sign(
        { user },
        {
          secret: this.configService.get<string>('FORGOT_PASSWORD_SECRET'),
          expiresIn: '5m',
        },
      );
      return forgotPasswordToken;
    } catch (error) {
      this.logger.error('Failed to generate forgot password token', error.stack);
      throw new InternalServerErrorException('Failed to generate reset token');
    }
  }

  // forgot password
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    try {
      const { email } = forgotPasswordDto;

      this.logger.log(`Forgot password request for: ${email}`);

      const user = await this.prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        this.logger.warn(`Forgot password - user not found: ${email}`);
        throw new NotFoundException('User not found with this email!');
      }

      const forgotPasswordToken = await this.generateForgotPasswordLink(user);

      const resetPasswordUrl =
        this.configService.get<string>('CLIENT_SIDE_URI') +
        `/reset-password?verify=${forgotPasswordToken}`;

      // Send forgot password email only if not in test environment
      if (this.configService.get('NODE_ENV') !== 'test') {
        try {
          await this.emailService.sendMail({
            email,
            subject: 'Reset your Password!',
            template: './forgot-password',
            name: user.name,
            activationCode: resetPasswordUrl,
          });
          this.logger.log(`Password reset email sent to: ${email}`);
        } catch (emailError) {
          this.logger.warn(`Failed to send password reset email to ${email}:`, emailError.message);
          // Continue without failing - user will still get success message
        }
      } else {
        this.logger.log(`Skipped sending password reset email in test environment for: ${email}`);
      }

      return { message: 'Password reset email sent successfully!' };

    } catch (error) {
      this.logger.error(`Forgot password failed for email: ${forgotPasswordDto.email}`, error.stack);
      
      if (error instanceof NotFoundException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Password reset request failed. Please try again later.');
    }
  }

  // reset password
  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    try {
      const { password, activationToken } = resetPasswordDto;

      this.logger.log('Password reset attempt');

      // Decode and verify token
      let decoded: any;
      try {
        decoded = this.jwtService.verify(activationToken, {
          secret: this.configService.get<string>('FORGOT_PASSWORD_SECRET'),
        });
      } catch (jwtError) {
        this.logger.warn('Invalid or expired reset token');
        throw new BadRequestException('Invalid or expired reset token!');
      }

      if (!decoded || !decoded.user) {
        throw new BadRequestException('Invalid token format!');
      }

      // Verify user still exists
      const existingUser = await this.prisma.user.findUnique({
        where: { id: decoded.user.id },
      });

      if (!existingUser) {
        throw new NotFoundException('User not found!');
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Update user password
      const user = await this.prisma.user.update({
        where: { id: decoded.user.id },
        data: { password: hashedPassword },
      });

      this.logger.log(`Password reset successfully for user: ${user.email}`);

      return { user };

    } catch (error) {
      this.logger.error('Password reset failed', error.stack);
      
      if (error instanceof BadRequestException || error instanceof NotFoundException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Password reset failed. Please try again later.');
    }
  }

  // get logged in user
  async getLoggedInUser(req: any) {
    try {
      const user = req.user;
      const refreshToken = req.refreshtoken;
      const accessToken = req.accesstoken;

      if (!user) {
        throw new UnauthorizedException('User not found in request');
      }

      // Fetch fresh user data with avatar
      const freshUser = await this.prisma.user.findUnique({
        where: { id: user.id },
        include: { avatar: true }
      });

      if (!freshUser) {
        throw new NotFoundException('User not found');
      }

      return { user: freshUser, refreshToken, accessToken };

    } catch (error) {
      this.logger.error('Get logged in user failed', error.stack);
      
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      
      throw new InternalServerErrorException('Failed to get user information');
    }
  }

  // log out user
  async logout(req: any) {
    try {
      const userId = req.user?.id;
      
      if (userId) {
        this.logger.log(`User logged out: ${userId}`);
      }

      // Clear user data from request
      req.user = null;
      req.refreshtoken = null;
      req.accesstoken = null;

      return { message: 'Logged out successfully!' };

    } catch (error) {
      this.logger.error('Logout failed', error.stack);
      throw new InternalServerErrorException('Logout failed');
    }
  }

  // get all users service
  async getUsers() {
    try {
      this.logger.log('Fetching all users');

      const users = await this.prisma.user.findMany({
        include: { avatar: true },
        orderBy: { createdAt: 'desc' }
      });

      return users;

    } catch (error) {
      this.logger.error('Failed to fetch users', error.stack);
      
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        throw new BadRequestException('Database query failed');
      }
      
      throw new InternalServerErrorException('Failed to fetch users');
    }
  }

  // Utility method to validate environment variables
  private validateRequiredConfig() {
    const requiredEnvVars = [
      'ACTIVATION_SECRET',
      'ACCESS_TOKEN_SECRET', 
      'REFRESH_TOKEN_SECRET',
      'FORGOT_PASSWORD_SECRET',
      'CLIENT_SIDE_URI'
    ];

    for (const envVar of requiredEnvVars) {
      if (!this.configService.get<string>(envVar)) {
        this.logger.error(`Missing required environment variable: ${envVar}`);
        throw new InternalServerErrorException('Server configuration error');
      }
    }
  }
}