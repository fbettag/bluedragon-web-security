/**
 * BlueDragon Web Security - Safety Filters
 * Blocklists and safety mechanisms to prevent accidental damage
 */

// Payment and billing endpoint patterns - NEVER auto-probe these
export const BLOCKED_ENDPOINT_PATTERNS = [
  // Payment processing
  /\/pay(ment)?s?/i,
  /\/billing/i,
  /\/checkout/i,
  /\/cart/i,
  /\/subscribe/i,
  /\/subscription/i,
  /\/purchase/i,
  /\/buy/i,
  /\/order/i,
  /\/transaction/i,

  // Payment providers
  /\/stripe/i,
  /\/paypal/i,
  /\/braintree/i,
  /\/square/i,
  /\/adyen/i,
  /\/klarna/i,
  /\/affirm/i,
  /\/afterpay/i,
  /\/clearpay/i,
  /\/shopify.*pay/i,
  /\/apple.*pay/i,
  /\/google.*pay/i,

  // Financial
  /\/bank/i,
  /\/transfer/i,
  /\/wire/i,
  /\/refund/i,
  /\/chargeback/i,
  /\/dispute/i,
  /\/payout/i,
  /\/withdraw/i,
  /\/deposit/i,
  /\/wallet/i,

  // Billing documents
  /\/invoice/i,
  /\/receipt/i,
  /\/statement/i,

  // Credit/debit card
  /\/card/i,
  /\/credit/i,
  /\/debit/i,
  /\/cvv/i,
  /\/cvc/i,
  /\/expir/i,

  // Donations/tips
  /\/donate/i,
  /\/donation/i,
  /\/tip(ping)?/i,
  /\/support.*creator/i,
  /\/sponsor/i,

  // Crypto
  /\/crypto/i,
  /\/bitcoin/i,
  /\/ethereum/i,
  /\/wallet.*address/i,

  // ACH/Direct debit
  /\/ach/i,
  /\/direct.*debit/i,
  /\/routing.*number/i,
  /\/account.*number/i,

  // Price/upgrade
  /\/upgrade/i,
  /\/downgrade/i,
  /\/pricing/i,
  /\/plan/i,
  /\/tier/i
];

// Sensitive action patterns - require user confirmation
export const CONFIRMATION_REQUIRED_PATTERNS = [
  // Account management
  /\/delete.*account/i,
  /\/remove.*account/i,
  /\/close.*account/i,
  /\/deactivate/i,
  /\/terminate/i,

  // Password/auth
  /\/password/i,
  /\/reset/i,
  /\/change.*email/i,
  /\/change.*phone/i,
  /\/2fa/i,
  /\/mfa/i,
  /\/totp/i,

  // Data export/deletion
  /\/export.*data/i,
  /\/download.*data/i,
  /\/gdpr/i,
  /\/data.*request/i,
  /\/delete.*data/i,
  /\/purge/i,

  // Admin actions
  /\/admin/i,
  /\/sudo/i,
  /\/impersonate/i,
  /\/takeover/i,

  // Destructive operations
  /\/destroy/i,
  /\/remove/i,
  /\/drop/i,
  /\/truncate/i,
  /\/wipe/i
];

// HTTP methods that are potentially destructive
export const DESTRUCTIVE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// Content types that might indicate form submission
export const FORM_CONTENT_TYPES = [
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain'
];

/**
 * Check if an endpoint should be blocked from automatic probing
 * @param {string} url - The URL to check
 * @returns {boolean} - True if blocked
 */
export function isBlockedEndpoint(url) {
  const urlLower = url.toLowerCase();
  return BLOCKED_ENDPOINT_PATTERNS.some(pattern => pattern.test(urlLower));
}

/**
 * Check if an action requires user confirmation
 * @param {string} url - The URL to check
 * @param {string} method - HTTP method
 * @returns {boolean} - True if confirmation required
 */
export function requiresConfirmation(url, method = 'GET') {
  // All blocked endpoints require confirmation if manually tested
  if (isBlockedEndpoint(url)) {
    return true;
  }

  // Check confirmation patterns
  const urlLower = url.toLowerCase();
  if (CONFIRMATION_REQUIRED_PATTERNS.some(pattern => pattern.test(urlLower))) {
    return true;
  }

  // Destructive methods on unknown endpoints
  if (DESTRUCTIVE_METHODS.includes(method.toUpperCase())) {
    return true;
  }

  return false;
}

/**
 * Sanitize a payload to remove actually dangerous content
 * This is a last-line defense - scanners should already use safe payloads
 * @param {string} payload - The payload to sanitize
 * @returns {string} - Sanitized payload
 */
export function sanitizePayload(payload) {
  // Remove shell commands that could cause damage
  const dangerousPatterns = [
    /rm\s+-rf/gi,
    /rm\s+-r/gi,
    /del\s+\/f/gi,
    /format\s+c:/gi,
    /mkfs/gi,
    /dd\s+if=/gi,
    />\s*\/dev\//gi,
    /shutdown/gi,
    /reboot/gi,
    /halt/gi,
    /init\s+0/gi,
    /chmod\s+777/gi,
    /chmod\s+-R/gi,
    /chown\s+-R/gi,
    /wget.*\|\s*sh/gi,
    /curl.*\|\s*sh/gi,
    /curl.*\|\s*bash/gi,
    /nc\s+-e/gi,
    /bash\s+-i/gi,
    /python.*-c.*socket/gi,
    /perl.*-e.*socket/gi,
    /ruby.*-rsocket/gi,
    /DROP\s+TABLE/gi,
    /DROP\s+DATABASE/gi,
    /TRUNCATE/gi,
    /DELETE\s+FROM/gi,
    /UPDATE.*SET.*WHERE/gi
  ];

  let sanitized = payload;
  for (const pattern of dangerousPatterns) {
    sanitized = sanitized.replace(pattern, '[BLOCKED]');
  }

  return sanitized;
}

/**
 * Generate a safe unique identifier for OOB detection
 * @returns {string} - Unique identifier
 */
export function generateSafeId() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let id = 'wd-';  // BlueDragon prefix
  for (let i = 0; i < 16; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
}

/**
 * Check if a response indicates we might have caused unintended effects
 * @param {number} status - HTTP status code
 * @param {string} body - Response body
 * @returns {Object} - { safe: boolean, reason: string }
 */
export function checkResponseSafety(status, body) {
  // 5xx errors might indicate we broke something
  if (status >= 500) {
    return {
      safe: false,
      reason: `Server error (${status}) - probe may have caused issues`
    };
  }

  // Check for error patterns in body
  const errorPatterns = [
    /exception/i,
    /fatal error/i,
    /stack trace/i,
    /segmentation fault/i,
    /out of memory/i,
    /database.*error/i,
    /sql.*error/i
  ];

  const bodyLower = (body || '').toLowerCase();
  for (const pattern of errorPatterns) {
    if (pattern.test(bodyLower)) {
      return {
        safe: false,
        reason: `Response contains error pattern: ${pattern.source}`
      };
    }
  }

  return { safe: true, reason: null };
}

/**
 * Rate limiter class for controlling request frequency
 */
export class RateLimiter {
  constructor(requestsPerSecond = 5) {
    this.requestsPerSecond = requestsPerSecond;
    this.queue = [];
    this.lastRequestTime = 0;
    this.interval = 1000 / requestsPerSecond;
  }

  async throttle() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;

    if (timeSinceLastRequest < this.interval) {
      await new Promise(resolve =>
        setTimeout(resolve, this.interval - timeSinceLastRequest)
      );
    }

    this.lastRequestTime = Date.now();
  }

  setRate(requestsPerSecond) {
    this.requestsPerSecond = requestsPerSecond;
    this.interval = 1000 / requestsPerSecond;
  }
}

/**
 * Request logger for tracking what we've sent (for accountability)
 */
export class RequestLogger {
  constructor(maxEntries = 1000) {
    this.maxEntries = maxEntries;
    this.entries = [];
  }

  log(request) {
    const entry = {
      timestamp: Date.now(),
      url: request.url,
      method: request.method,
      headers: this.sanitizeHeaders(request.headers),
      bodyPreview: this.truncate(request.body, 500),
      scanner: request.scanner || 'unknown'
    };

    this.entries.push(entry);

    // Trim if over limit
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries);
    }

    return entry;
  }

  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];

    for (const header of sensitiveHeaders) {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  truncate(str, maxLength) {
    if (!str) return null;
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...[truncated]';
  }

  getEntries(limit = 100) {
    return this.entries.slice(-limit);
  }

  clear() {
    this.entries = [];
  }

  export() {
    return JSON.stringify(this.entries, null, 2);
  }
}

export default {
  BLOCKED_ENDPOINT_PATTERNS,
  CONFIRMATION_REQUIRED_PATTERNS,
  DESTRUCTIVE_METHODS,
  FORM_CONTENT_TYPES,
  isBlockedEndpoint,
  requiresConfirmation,
  sanitizePayload,
  generateSafeId,
  checkResponseSafety,
  RateLimiter,
  RequestLogger
};
