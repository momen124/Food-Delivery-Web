import { BadRequestException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../../../prisma/Prisma.service";
import { LoginDto, RegisterDto } from "./dto/user.dto";
import * as bcrypt from 'bcrypt';
import { EmailService } from "./email/email.service";
import { Response } from 'express';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: string; 
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  // Register user
  async register(registerDto: RegisterDto): Promise<any> {
    const { name, email, password, phone_number } = registerDto;

    const isEmailExist = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (isEmailExist) {
      throw new BadRequestException('User already exists with this email!');
    }

    const isPhoneNumberExist = await this.prisma.user.findFirst({
      where: {
        email,
        phone_number,
      },
    });

    if (isPhoneNumberExist) {
      throw new BadRequestException('User already exists with this phone number!');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        phone_number,
      },
    });

    const activationToken = await this.createActivationToken(user);
    const activationCode = activationToken.activationCode;

    await this.emailService.sendMail({
      email,
      subject: 'Activate your account!',
      template: './activation-mail',
      name,
      activationCode,
    });

    return { user };
  }

  async createActivationToken(user: UserData) {
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
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new BadRequestException('Invalid email or password');
    }

    const token = this.jwtService.sign({ userId: user.id });
    return { token };
  }

  async getUsers() {
    return this.prisma.user.findMany({});
  }
}
