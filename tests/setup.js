/**
 * Jest Test Setup - BlueDragon Web Security
 */

// Mock Chrome Extension APIs
require('./mocks/chrome');

// Increase timeout for integration tests
jest.setTimeout(10000);
