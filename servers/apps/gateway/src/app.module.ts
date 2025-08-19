import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloGatewayDriver, ApolloGatewayDriverConfig } from '@nestjs/apollo';
import { IntrospectAndCompose } from '@apollo/gateway';
import { AppService } from './app.service';
import { AppController } from './app.controller';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloGatewayDriverConfig>({
      driver: ApolloGatewayDriver,
      gateway: {
        supergraphSdl: new IntrospectAndCompose({
          subgraphs: [
            {
              name: 'users',
              url: 'http://localhost:4001/graphql',
            },
          ],
          // Add polling for service discovery
          pollIntervalInMs: 10000, // Poll every 10 seconds
        }),
      },
      // Enable introspection and playground for development
      server: {
        introspection: true,
        playground: true,
        // Add error handling
        formatError: (error) => {
          console.error('GraphQL Error:', error);
          return {
            message: error.message,
            // Only include error details in development
            ...(process.env.NODE_ENV === 'development' && {
              locations: error.locations,
              path: error.path,
              extensions: error.extensions,
            }),
          };
        },
        // Add context to pass through headers
        context: ({ req }) => ({
          headers: req.headers,
        }),
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}