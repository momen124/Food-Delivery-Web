import * as request from 'supertest';
import { INestApplication } from '@nestjs/common';

export class TestUtils {
  constructor(private app: INestApplication) {}

  // Helper to create unique test data
  generateTestUser(suffix?: string) {
    const timestamp = Date.now();
    const uniqueSuffix = suffix || timestamp.toString();
    
    return {
      name: `Test User ${uniqueSuffix}`,
      email: `test${uniqueSuffix}@example.com`,
      password: 'TestPassword123!',
      phone_number: `+123456${uniqueSuffix.slice(-4)}`,
    };
  }

  // Helper for GraphQL requests
  async graphqlRequest(
    query: string,
    variables?: Record<string, any>,
    headers: Record<string, string> = {}
  ) {
    return request(this.app.getHttpServer())
      .post('/graphql')
      .set({
        'Content-Type': 'application/json',
        ...headers,
      })
      .send({ query, variables });
  }

  // Helper for authenticated GraphQL requests
  async authenticatedGraphqlRequest(
    query: string,
    accessToken: string,
    refreshToken: string,
    variables?: Record<string, any>,
    additionalHeaders: Record<string, string> = {}
  ) {
    return this.graphqlRequest(query, variables, {
      'accesstoken': accessToken,
      'refreshtoken': refreshToken,
      ...additionalHeaders,
    });
  }

  // Helper to register and activate a user
  async registerAndActivateUser(userData?: any) {
    const user = userData || this.generateTestUser();
    
    // Register user
    const registerMutation = `
      mutation Register($registerDto: RegisterDto!) {
        register(registerDto: $registerDto) {
          activationToken
          error {
            message
          }
        }
      }
    `;

    const registerResponse = await this.graphqlRequest(registerMutation, {
      registerDto: user,
    });

    if (registerResponse.body.data.register.error) {
      throw new Error(`Registration failed: ${registerResponse.body.data.register.error.message}`);
    }

    const activationToken = registerResponse.body.data.register.activationToken;

    // Get activation code from token (for testing purposes)
    // Note: In production, this would come from email
    const jwt = require('jsonwebtoken');
    const decoded = jwt.decode(activationToken);
    const activationCode = decoded.activationCode;

    // Activate user
    const activationMutation = `
      mutation ActivateUser($activationDto: ActivationDto!) {
        activateUser(activationDto: $activationDto) {
          user {
            id
            email
          }
          error {
            message
          }
        }
      }
    `;

    const activationResponse = await this.graphqlRequest(activationMutation, {
      activationDto: {
        activationToken,
        activationCode,
      },
    });

    if (activationResponse.body.data.activateUser.error) {
      throw new Error(`Activation failed: ${activationResponse.body.data.activateUser.error.message}`);
    }

    return {
      user,
      userId: activationResponse.body.data.activateUser.user.id,
    };
  }

  // Helper to login and get tokens
  async loginUser(email: string, password: string) {
    const loginMutation = `
      mutation Login($loginDto: LoginDto!) {
        login(loginDto: $loginDto) {
          user {
            id
            email
          }
          accessToken
          refreshToken
          error {
            message
          }
        }
      }
    `;

    const response = await this.graphqlRequest(loginMutation, {
      loginDto: { email, password },
    });

    if (response.body.data.login.error) {
      throw new Error(`Login failed: ${response.body.data.login.error.message}`);
    }

    return {
      user: response.body.data.login.user,
      accessToken: response.body.data.login.accessToken,
      refreshToken: response.body.data.login.refreshToken,
    };
  }

  // Helper to clean up test users
  async cleanupUser(userId: string, prismaService: any) {
    try {
      await prismaService.user.delete({ where: { id: userId } });
    } catch (error) {
      console.warn(`Cleanup warning: ${error.message}`);
    }
  }

  // Helper to wait for async operations
  async wait(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}