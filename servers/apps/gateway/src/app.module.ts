import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloGatewayDriver, ApolloGatewayDriverConfig } from '@nestjs/apollo';
import { IntrospectAndCompose } from '@apollo/gateway';
import { UsersModule } from 'apps/users/src/users.module';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloGatewayDriverConfig>({
      driver: ApolloGatewayDriver,
      gateway: {
        supergraphSdl: new IntrospectAndCompose({
          subgraphs: [
            // Define your subgraphs here
          ],
        }),
      },
    }),
    UsersModule,  // Register the UsersModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
