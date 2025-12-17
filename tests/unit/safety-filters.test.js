/**
 * Safety Filter Tests - BlueDragon Web Security
 * Tests the safety mechanisms for safe scanning
 */

// Blocked endpoint detection
function isBlockedEndpoint(path) {
  const blockedPatterns = [
    /\/pay/i, /\/payment/i, /\/checkout/i, /\/billing/i,
    /\/stripe/i, /\/paypal/i, /\/braintree/i,
    /\/bank/i, /\/transfer/i, /\/wallet/i, /\/refund/i,
    /\/card/i, /\/cvv/i, /\/expir/i,
    /\/crypto/i, /\/bitcoin/i, /\/ethereum/i,
    /\/subscribe/i, /\/subscription/i
  ];
  return blockedPatterns.some(p => p.test(path));
}

// Confirmation required detection
function requiresConfirmation(path) {
  const confirmPatterns = [
    /\/delete/i, /\/destroy/i, /\/remove/i,
    /\/password/i, /\/reset/i, /\/change-password/i,
    /\/admin/i, /\/ban/i, /\/suspend/i,
    /\/export/i, /\/download-all/i
  ];
  return confirmPatterns.some(p => p.test(path));
}

// Dangerous payload detection
function isDangerousPayload(payload) {
  const dangerousPatterns = [
    /rm\s+-rf/i, /del\s+\/f/i, /dd\s+if=/i,
    /eval\s*\(/i, /new\s+Function/i,
    /DROP\s+TABLE/i, /DELETE\s+FROM/i,
    /;\s*--/i, /OR\s+1\s*=\s*1/i,
    /chmod\s+777/i, /mkfs/i
  ];
  return dangerousPatterns.some(p => p.test(payload));
}

// Header sanitization
function sanitizeHeaders(headers) {
  const sensitiveHeaders = [
    'authorization', 'cookie', 'x-api-key', 'x-auth-token',
    'x-access-token', 'api-key', 'apikey', 'bearer'
  ];
  const sanitized = {};
  for (const [key, value] of Object.entries(headers)) {
    if (sensitiveHeaders.some(h => key.toLowerCase().includes(h))) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

describe('Safety Filters', () => {

  describe('isBlockedEndpoint', () => {
    test('blocks payment endpoints', () => {
      expect(isBlockedEndpoint('/api/pay')).toBe(true);
      expect(isBlockedEndpoint('/api/payment')).toBe(true);
      expect(isBlockedEndpoint('/checkout')).toBe(true);
      expect(isBlockedEndpoint('/billing/update')).toBe(true);
    });

    test('blocks Stripe endpoints', () => {
      expect(isBlockedEndpoint('/stripe/webhook')).toBe(true);
      expect(isBlockedEndpoint('/api/stripe/charge')).toBe(true);
    });

    test('blocks PayPal endpoints', () => {
      expect(isBlockedEndpoint('/paypal/checkout')).toBe(true);
      expect(isBlockedEndpoint('/api/paypal')).toBe(true);
    });

    test('blocks financial endpoints', () => {
      expect(isBlockedEndpoint('/bank/transfer')).toBe(true);
      expect(isBlockedEndpoint('/wallet/withdraw')).toBe(true);
      expect(isBlockedEndpoint('/api/refund')).toBe(true);
    });

    test('blocks credit card endpoints', () => {
      expect(isBlockedEndpoint('/card/add')).toBe(true);
      expect(isBlockedEndpoint('/api/cvv')).toBe(true);
    });

    test('allows non-payment endpoints', () => {
      expect(isBlockedEndpoint('/api/users')).toBe(false);
      expect(isBlockedEndpoint('/api/products')).toBe(false);
      expect(isBlockedEndpoint('/dashboard')).toBe(false);
    });
  });

  describe('requiresConfirmation', () => {
    test('requires confirmation for delete actions', () => {
      expect(requiresConfirmation('/api/account/delete')).toBe(true);
      expect(requiresConfirmation('/user/destroy')).toBe(true);
    });

    test('requires confirmation for password changes', () => {
      expect(requiresConfirmation('/api/password/reset')).toBe(true);
      expect(requiresConfirmation('/auth/change-password')).toBe(true);
    });

    test('requires confirmation for admin actions', () => {
      expect(requiresConfirmation('/admin/users/ban')).toBe(true);
      expect(requiresConfirmation('/api/admin/config')).toBe(true);
    });

    test('does not require confirmation for read actions', () => {
      expect(requiresConfirmation('/api/users')).toBe(false);
      expect(requiresConfirmation('/api/products/list')).toBe(false);
    });
  });

  describe('isDangerousPayload', () => {
    test('blocks shell commands', () => {
      expect(isDangerousPayload('rm -rf /')).toBe(true);
      expect(isDangerousPayload('del /f /s')).toBe(true);
      expect(isDangerousPayload('dd if=/dev/zero')).toBe(true);
    });

    test('blocks code injection', () => {
      expect(isDangerousPayload('eval(atob("..."))')).toBe(true);
      expect(isDangerousPayload('new Function("...")')).toBe(true);
    });

    test('blocks SQL injection payloads', () => {
      expect(isDangerousPayload("'; DROP TABLE users;--")).toBe(true);
      expect(isDangerousPayload('1 OR 1=1')).toBe(true);
    });

    test('allows safe payloads', () => {
      expect(isDangerousPayload('{"name":"test"}')).toBe(false);
      expect(isDangerousPayload('hello world')).toBe(false);
    });
  });

  describe('sanitizeHeaders', () => {
    test('removes Authorization header', () => {
      const headers = {
        'Authorization': 'Bearer token123',
        'Content-Type': 'application/json'
      };
      const sanitized = sanitizeHeaders(headers);
      expect(sanitized['Authorization']).toBe('[REDACTED]');
      expect(sanitized['Content-Type']).toBe('application/json');
    });

    test('removes Cookie header', () => {
      const headers = {
        'Cookie': 'session=abc123',
        'Accept': 'application/json'
      };
      const sanitized = sanitizeHeaders(headers);
      expect(sanitized['Cookie']).toBe('[REDACTED]');
    });

    test('removes API key headers', () => {
      const headers = {
        'X-API-Key': 'secret123',
        'X-Auth-Token': 'token456'
      };
      const sanitized = sanitizeHeaders(headers);
      expect(sanitized['X-API-Key']).toBe('[REDACTED]');
      expect(sanitized['X-Auth-Token']).toBe('[REDACTED]');
    });

    test('preserves safe headers', () => {
      const headers = {
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0'
      };
      const sanitized = sanitizeHeaders(headers);
      expect(sanitized['Content-Type']).toBe('application/json');
      expect(sanitized['Accept']).toBe('*/*');
    });
  });
});
