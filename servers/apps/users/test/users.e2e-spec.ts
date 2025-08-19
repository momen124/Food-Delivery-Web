import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { UsersModule } from '../src/users.module';
import { ConfigModule } from '@nestjs/config';
import { PrismaService } from '../../../prisma/prisma.service';
import { GlobalExceptionFilter } from '../src/filters/global-exception.filter';
import configuration, { validateConfig } from '../src/config/configuration';
import * as Joi from 'joi';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

describe('Food Delivery Users Service E2E Tests', () => {
  let app: INestApplication;
  let prismaService: PrismaService;
  
  // Test data
  const uniqueSuffix = Date.now();
  const testUser = {
    name: 'Test User E2E',
    email: `teste2e${uniqueSuffix}@example.com`,
    password: 'TestPassword123!',
    phone_number: '+1234567890',
  };

  let activationToken: string;
  let accessToken: string;
  let refreshToken: string;
  let userId: string;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [configuration],
          validate: validateConfig,
          validationSchema: Joi.object({
            DATABASE_URL: Joi.string().required(),
            ACTIVATION_SECRET: Joi.string().min(32).required(),
            ACCESS_TOKEN_SECRET: Joi.string().min(32).required(),
            REFRESH_TOKEN_SECRET: Joi.string().min(32).required(),
            FORGOT_PASSWORD_SECRET: Joi.string().min(32).required(),
            CLIENT_SIDE_URI: Joi.string().uri().required(),
            SMTP_HOST: Joi.string().required(),
            SMTP_MAIL: Joi.string().email().required(),
            SMTP_PASSWORD: Joi.string().required(),
            PORT: Joi.number().port().default(4001),
            NODE_ENV: Joi.string().default('test'),
            CSRF_SECRET: Joi.string().min(32).optional(),
            RATE_LIMIT_TTL: Joi.number().default(60),
            RATE_LIMIT_MAX: Joi.number().default(100),
            SESSION_SECRET: Joi.string().min(32).optional(),
            TWO_FACTOR_APP_NAME: Joi.string().default('Food Delivery'),
          }),
        }),
        UsersModule,
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    prismaService = moduleRef.get<PrismaService>(PrismaService);

    // Apply the same configuration as main.ts
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
        validationError: {
          target: false,
          value: false,
        },
      }),
    );

    app.useGlobalFilters(new GlobalExceptionFilter());

    app.enableCors({
      origin: ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'accesstoken', 'refreshtoken', 'x-csrf-token'],
    });

    await app.init();
  });

  afterAll(async () => {
    // Cleanup test data
    if (userId) {
      try {
        await prismaService.user.delete({ where: { id: userId } });
      } catch (error) {
        console.log('Cleanup error (user may not exist):', error.message);
      }
    }
    
    await app.close();
  });

  // Helper function to send GraphQL requests
  const graphqlRequest = (
    query: string, 
    variables?: Record<string, any>, 
    headers: Record<string, string> = {}
  ) =>
    request(app.getHttpServer())
      .post('/graphql')
      .set({
        'Content-Type': 'application/json',
        ...headers,
      })
      .send({ query, variables });

  describe('User Registration Flow', () => {
    it('should register a new user successfully', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
              name
              email
              phone_number
              role
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
        registerDto: testUser,
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.register).toBeDefined();
      expect(response.body.data.register.activationToken).toBeDefined();
      expect(response.body.data.register.error).toBeNull();
      
      // Store activation token for next test
      activationToken = response.body.data.register.activationToken;
    });

    it('should fail to register with duplicate email', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
        registerDto: testUser, // Same email as previous test
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.register.error).toBeDefined();
      expect(response.body.data.register.error.message).toContain('already exists');
      expect(response.body.data.register.user).toBeNull();
      expect(response.body.data.register.activationToken).toBeNull();
    });

    it('should fail with invalid email format', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
          ...testUser,
          email: 'invalid-email-format',
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.errors || response.body.data.register.error).toBeDefined();
    });

    it('should fail with weak password', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
          ...testUser,
          email: `weakpassword${uniqueSuffix}@example.com`,
          password: '123', // Weak password
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.errors || response.body.data.register.error).toBeDefined();
    });
  });

  describe('User Activation Flow', () => {
    it('should activate user with valid token and code', async () => {
      // First, decode the activation token to get the activation code
      const jwtService = app.get(JwtService);
      const configService = app.get(ConfigService);
      
      let activationCode: string;
      try {
        const decoded = jwtService.verify(activationToken, {
          secret: configService.get<string>('ACTIVATION_SECRET'),
        });
        activationCode = decoded.activationCode;
      } catch (error) {
        throw new Error('Failed to verify activation token: ' + error.message);
      }

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
          activationToken,
          activationCode,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.activateUser).toBeDefined();
      expect(response.body.data.activateUser.user).toBeDefined();
      expect(response.body.data.activateUser.user.email).toBe(testUser.email);
      expect(response.body.data.activateUser.error).toBeNull();
      
      // Store user ID for cleanup
      userId = response.body.data.activateUser.user.id;
    });

    it('should fail activation with invalid code', async () => {
      const mutation = `
        mutation ActivateUser($activationDto: ActivationDto!) {
          activateUser(activationDto: $activationDto) {
            user {
              id
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
          activationToken: activationToken || 'invalid-token',
          activationCode: '9999', // Wrong code
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.activateUser.error).toBeDefined();
      expect(response.body.data.activateUser.user).toBeNull();
    });
  });

  describe('User Login Flow', () => {
    it('should login user with valid credentials', async () => {
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
          email: testUser.email,
          password: testUser.password,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.login).toBeDefined();
      expect(response.body.data.login.user).toBeDefined();
      expect(response.body.data.login.accessToken).toBeDefined();
      expect(response.body.data.login.refreshToken).toBeDefined();
      expect(response.body.data.login.error).toBeNull();
      
      // Store tokens for authenticated requests
      accessToken = response.body.data.login.accessToken;
      refreshToken = response.body.data.login.refreshToken;
    });

    it('should fail login with invalid credentials', async () => {
      const mutation = `
        mutation Login($loginDto: LoginDto!) {
          login(loginDto: $loginDto) {
            user {
              id
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
          email: testUser.email,
          password: 'wrongpassword',
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.login.error).toBeDefined();
      expect(response.body.data.login.user).toBeNull();
      expect(response.body.data.login.accessToken).toBeNull();
    });

    it('should fail login with non-existent user', async () => {
      const mutation = `
        mutation Login($loginDto: LoginDto!) {
          login(loginDto: $loginDto) {
            user {
              id
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
          email: 'nonexistent@example.com',
          password: testUser.password,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.login.error).toBeDefined();
      expect(response.body.data.login.user).toBeNull();
    });
  });

  describe('Authenticated User Operations', () => {
    it('should get logged-in user with valid tokens', async () => {
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

      const response = await graphqlRequest(query, {}, {
        'accesstoken': accessToken,
        'refreshtoken': refreshToken,
      });

      expect(response.status).toBe(200);
      expect(response.body.data.getLoggedInUser).toBeDefined();
      expect(response.body.data.getLoggedInUser.user).toBeDefined();
      expect(response.body.data.getLoggedInUser.user.email).toBe(testUser.email);
      expect(response.body.data.getLoggedInUser.error).toBeNull();
    });

    it('should fail to get logged-in user without tokens', async () => {
      const query = `
        query GetLoggedInUser {
          getLoggedInUser {
            user {
              id
            }
            error {
              message
              code
            }
          }
        }
      `;

      const response = await graphqlRequest(query);

      expect(response.status).toBe(200);
      expect(response.body.errors).toBeDefined();
      expect(response.body.errors[0].message).toContain('Authentication tokens are required');
    });

    it('should get all users with authentication', async () => {
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
          }
        }
      `;

      const response = await graphqlRequest(query, {}, {
        'accesstoken': accessToken,
        'refreshtoken': refreshToken,
      });

      expect(response.status).toBe(200);
      expect(response.body.data.getUsers).toBeDefined();
      expect(Array.isArray(response.body.data.getUsers)).toBe(true);
      expect(response.body.data.getUsers.length).toBeGreaterThan(0);
    });

    it('should logout user successfully', async () => {
      const query = `
        query LogoutUser {
          logOutUser {
            message
          }
        }
      `;

      const response = await graphqlRequest(query, {}, {
        'accesstoken': accessToken,
        'refreshtoken': refreshToken,
      });

      expect(response.status).toBe(200);
      expect(response.body.data.logOutUser).toBeDefined();
      expect(response.body.data.logOutUser.message).toBe('Logged out successfully!');
    });
  });

  describe('Password Reset Flow', () => {
    it('should initiate forgot password for existing user', async () => {
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
          email: testUser.email,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.forgotPassword).toBeDefined();
      expect(response.body.data.forgotPassword.message).toBeDefined();
      expect(response.body.data.forgotPassword.error).toBeNull();
    });

    it('should fail forgot password for non-existent user', async () => {
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
          email: 'nonexistent@example.com',
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.data.forgotPassword.error).toBeDefined();
      expect(response.body.data.forgotPassword.message).toBeNull();
    });
  });

  describe('Input Validation Tests', () => {
    it('should validate required fields in registration', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
          name: '', // Empty name
          email: `emptyname${uniqueSuffix}@example.com`,
          password: testUser.password,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.errors || response.body.data.register.error).toBeDefined();
    });

    it('should validate email format', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
          name: 'Test User',
          email: 'invalid.email',
          password: testUser.password,
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.errors || response.body.data.register.error).toBeDefined();
    });

    it('should validate password complexity', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
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
          name: 'Test User',
          email: `weakpass${uniqueSuffix}@example.com`,
          password: 'weak',
        },
      };

      const response = await graphqlRequest(mutation, variables);

      expect(response.status).toBe(200);
      expect(response.body.errors || response.body.data.register.error).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed GraphQL queries', async () => {
      const malformedQuery = 'invalid graphql query {';

      const response = await graphqlRequest(malformedQuery);

      expect(response.status).toBe(400);
      expect(response.body.errors).toBeDefined();
    });

    it('should handle missing required variables', async () => {
      const mutation = `
        mutation Register($registerDto: RegisterDto!) {
          register(registerDto: $registerDto) {
            user {
              id
            }
            error {
              message
            }
          }
        }
      `;

      // Missing variables
      const response = await graphqlRequest(mutation);

      expect(response.status).toBe(200);
      expect(response.body.errors).toBeDefined();
    });
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      expect(response.body).toEqual({
        status: 'OK',
        service: 'Users Service',
        timestamp: expect.any(String),
      });
    });
  });
});