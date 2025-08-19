
// apps/users/test/setup-e2e.ts
import { config } from 'dotenv';
import { join } from 'path';

// Load test environment variables
config({ path: join(__dirname, '../../../.env.test') });

// Global test setup
beforeAll(async () => {
  // Set test environment
  process.env.NODE_ENV = 'test';
  
  // Disable console logs during tests (optional)
  if (process.env.DISABLE_TEST_LOGS === 'true') {
    console.log = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();
  }
});

// Global test teardown
afterAll(async () => {
  // Any global cleanup can go here
});

// Increase timeout for async operations
jest.setTimeout(30000);