// apps/users/src/users.e2e-spec.ts
import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { UsersModule } from '../src/users.module';
import { ConfigModule } from '@nestjs/config';

describe('Food Delivery GraphQL API (E2E)', () => {
  let app: INestApplication;

  const accessToken = 'f8680540a6b1f4ef0171422887bd71753f87df6f0239cdb6a7b42da62f347496b';
  const refreshToken = '7e387427e1dd13036114da66e894983dae9193713f43d384a4636f05220d84f';
  const csrfToken = '9a92725e8a6fae055aac3e8c2dbbd9c5a9eb71e20ded0eaca20d4fb64edf42c4';

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        UsersModule,
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: ['.env', 'apps/users/.env'],
        }),
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.listen(4001); // Test against users service
    app.enableCors(); // Enable CORS for testing
  });

  afterAll(async () => {
    await app.close();
  });

  // Helper function to send GraphQL requests
  const graphqlRequest = (query: string, variables?: Record<string, any>, authHeaders: Record<string, string> = {}) =>
    request(app.getHttpServer())
      .post('/graphql')
      .set({
        ...authHeaders,
        'Authorization': `Bearer ${accessToken}`,
        'X-CSRF-Token': csrfToken,
      })
      .send({ query, variables })
      .expect(200);

  // Test Cases for Mutations
  it('should register a new user', async () => {
    const mutation = `
      mutation Register($registerDto: RegisterDto!) {
        register(registerDto: $registerDto) {
          user {
            id
            name
            email
            phone_number
            role
            createdAt
            updatedAt
          }
          activationToken
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      registerDto: {
        name: 'Test User',
        email: 'test.new@example.com', // Unique email
        password: 'Test123!@#',
        phone_number: '+1234567890',
      },
    };

    const response = await graphqlRequest(mutation, variables, {}); // No auth for registration
    expect(response.body.data.register).toBeDefined();
    expect(response.body.data.register.user).toHaveProperty('id');
    expect(response.body.data.register.user.name).toBe('Test User');
    expect(response.body.data.register.activationToken).toBeDefined();
    expect(response.body.data.register.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  it('should activate a user', async () => {
    // Assume activationToken is from the previous register test (mocked here)
    const mutation = `
      mutation ActivateUser($activationDto: ActivationDto!) {
        activateUser(activationDto: $activationDto) {
          user {
            id
            name
            email
            phone_number
            role
            createdAt
            updatedAt
            avatar {
              id
              public_id
              url
              userId
            }
          }
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      activationDto: {
        activationToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', // Mock token
        activationCode: '1234',
      },
    };

    const response = await graphqlRequest(mutation, variables, {});
    expect(response.body.data.activateUser).toBeDefined();
    expect(response.body.data.activateUser.user).toHaveProperty('id');
    expect(response.body.data.activateUser.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  it('should login a user', async () => {
    const mutation = `
      mutation Login($loginDto: LoginDto!) {
        login(loginDto: $loginDto) {
          user {
            id
            name
            email
            phone_number
            role
            address
            createdAt
            updatedAt
            avatar {
              id
              public_id
              url
              userId
            }
          }
          accessToken
          refreshToken
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      loginDto: {
        email: 'test.new@example.com',
        password: 'Test123!@#',
      },
    };

    const response = await graphqlRequest(mutation, variables, {});
    expect(response.body.data.login).toBeDefined();
    expect(response.body.data.login.user).toHaveProperty('id');
    expect(response.body.data.login.accessToken).toBeDefined();
    expect(response.body.data.login.refreshToken).toBeDefined();
    expect(response.body.data.login.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  it('should initiate forgot password', async () => {
    const mutation = `
      mutation ForgotPassword($forgotPasswordDto: ForgotPasswordDto!) {
        forgotPassword(forgotPasswordDto: $forgotPasswordDto) {
          message
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      forgotPasswordDto: {
        email: 'test.new@example.com',
      },
    };

    const response = await graphqlRequest(mutation, variables, {});
    expect(response.body.data.forgotPassword).toBeDefined();
    expect(response.body.data.forgotPassword.message).toBeDefined();
    expect(response.body.data.forgotPassword.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  it('should reset password', async () => {
    const mutation = `
      mutation ResetPassword($resetPasswordDto: ResetPasswordDto!) {
        resetPassword(resetPasswordDto: $resetPasswordDto) {
          user {
            id
            name
            email
            phone_number
            role
            createdAt
            updatedAt
          }
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      resetPasswordDto: {
        password: 'NewTest123!@#',
        activationToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', // Mock token
      },
    };

    const response = await graphqlRequest(mutation, variables, {});
    expect(response.body.data.resetPassword).toBeDefined();
    expect(response.body.data.resetPassword.user).toHaveProperty('id');
    expect(response.body.data.resetPassword.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  // Test Cases for Queries
  it('should get logged-in user', async () => {
    const query = `
      query GetLoggedInUser {
        getLoggedInUser {
          user {
            id
            name
            email
            phone_number
            role
            address
            createdAt
            updatedAt
            avatar {
              id
              public_id
              url
              userId
            }
          }
          accessToken
          refreshToken
          error {
            message
            code
          }
        }
      }
    `;

    const response = await graphqlRequest(query);
    expect(response.body.data.getLoggedInUser).toBeDefined();
    expect(response.body.data.getLoggedInUser.user).toHaveProperty('id');
    expect(response.body.data.getLoggedInUser.accessToken).toBeDefined();
    expect(response.body.data.getLoggedInUser.error).toBeNull();
    expect(response.body.errors).toBeUndefined();
  });

  it('should get all users', async () => {
    const query = `
      query GetUsers {
        getUsers {
          id
          name
          email
          phone_number
          role
          address
          createdAt
          updatedAt
          avatar {
            id
            public_id
            url
            userId
          }
        }
      }
    `;

    const response = await graphqlRequest(query);
    expect(response.body.data.getUsers).toBeDefined();
    expect(Array.isArray(response.body.data.getUsers)).toBe(true);
    expect(response.body.errors).toBeUndefined();
  });

  it('should logout user', async () => {
    const query = `
      query LogoutUser {
        logOutUser {
          message
        }
      }
    `;

    const response = await graphqlRequest(query);
    expect(response.body.data.logOutUser).toBeDefined();
    expect(response.body.data.logOutUser.message).toBeDefined();
    expect(response.body.errors).toBeUndefined();
  });

  // Test Security Features
  it('should fail mutation with invalid CSRF token', async () => {
    const mutation = `
      mutation Register($registerDto: RegisterDto!) {
        register(registerDto: $registerDto) {
          user {
            id
            name
            email
          }
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      registerDto: {
        name: 'CSRF Test',
        email: 'csrf@example.com',
        password: 'Test123!@#',
        phone_number: '+1234567890',
      },
    };

    const response = await graphqlRequest(mutation, variables, { 'X-CSRF-Token': 'invalid-csrf-token' });
    expect(response.body.data.register).toBeNull();
    expect(response.body.errors).toBeDefined();
    expect(response.body.errors[0].message).toContain('CSRF token validation failed');
  });

  it('should return RATE_LIMITED error on excessive requests', async () => {
    const mutation = `
      mutation Register($registerDto: RegisterDto!) {
        register(registerDto: $registerDto) {
          user {
            id
            name
            email
          }
          error {
            message
            code
          }
        }
      }
    `;

    const variables = {
      registerDto: {
        name: 'Rate Limit Test',
        email: 'ratelimit@example.com',
        password: 'Test123!@#',
        phone_number: '+1234567890',
      },
    };

    // Simulate multiple requests (mocked here; adjust based on rate limit config)
    for (let i = 0; i < 101; i++) {
      await graphqlRequest(mutation, variables, {});
    }
    const response = await graphqlRequest(mutation, variables, {});
    expect(response.body.data.register).toBeNull();
    expect(response.body.errors).toBeDefined();
    expect(response.body.errors[0].message).toContain('Too many requests');
  });
});