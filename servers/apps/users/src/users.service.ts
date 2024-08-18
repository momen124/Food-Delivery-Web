import { BadRequestException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../../../prisma/Prisma.service";
import { LoginDto, RegisterDto } from "./dto/user.dto";
import { response } from "express";
import *as bcrypt from 'bcrypt';
import { EmailService } from "./email/email.service";

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
  async register(registerDto: RegisterDto, res: Response) {
    const { name, email, password, phone_number } = registerDto;

    const isEmailExist = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (isEmailExist) {
      throw new BadRequestException('User already exists with this email!');
    }

    const isPhoneNumberExist = await this.prisma.user.findUnique({
      where: {
        unique_email_phone_number: {
          email,
          phone_number,
        },
      },
    });
    

    if (isPhoneNumberExist) {
      throw new BadRequestException('User already exists with this phone number!');
    }


    const hashedPassword = await bcrypt.hash(password, 10)

    const user = {
      
        name,
        email,
        password: hashedPassword,
        phone_number,
     
    };
    const activationToken = await this.createActivationToken(user);
    const activationCode = activationToken.activationCode;
await this.emailService
    return { user, response }; // Adjust if needed based on your logic
  }


  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();
    const token = this.jwtService.sign(
      {
        user,
        activationCode,
      },
      {
        secret: this.configService.get<string>('ACTIVATION_SECRET'), // Ensure it's 'string', not 'String'
        expiresIn: '5m',
      },
    );
    return { token, activationCode };
  }
  



    async Login(loginDto: LoginDto){
    const { email, password }= loginDto;
    const user = {
     
      email, 
      password,
    };
    return user;
    }

    async getUsers(){
    return this.prisma.user.findMany({})
    }
  }