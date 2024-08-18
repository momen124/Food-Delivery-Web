import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import {
  ApolloFederationDriver,
  ApolloFederationDriverConfig,
} from '@nestjs/apollo';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from './users.service';
import { PrismaService } from '../../../prisma/Prisma.service'; // Corrected path
import { UserResolver } from './user.resolver';
import { EmailModule } from './email/email.module';


@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    GraphQLModule.forRoot<ApolloFederationDriverConfig>({
      driver: ApolloFederationDriver,
      autoSchemaFile: {
        federation: 2,
      },
    }),
    EmailModule,
  ],
  controllers: [],
  providers: [
    UsersService,
    ConfigService,
    JwtService,
    PrismaService,
    UserResolver,
  ],
})
export class UsersModule {}