/**
 * Constants and CVE Database Tests - BlueDragon Web Security
 * Tests the CVE database and configuration constants
 */

// Severity levels
const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

// Severity colors
const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6'
};

// CVE Database (subset for testing)
const CVE_DATABASE = {
  'CVE-2025-55182': {
    name: 'React2Shell',
    type: 'RCE',
    severity: SEVERITY.CRITICAL,
    cvss: 10.0,
    description: 'Flight protocol deserialization leads to unauthenticated RCE'
  },
  'CVE-2025-29927': {
    name: 'Next.js Middleware Bypass',
    type: 'AUTH_BYPASS',
    severity: SEVERITY.CRITICAL,
    cvss: 9.1,
    description: 'x-middleware-subrequest header bypasses middleware authorization'
  },
  'CVE-2025-59052': {
    name: 'Angular SSR Race Condition',
    type: 'RACE_CONDITION',
    severity: SEVERITY.HIGH,
    cvss: 7.1,
    description: 'Global Platform Injector race condition leaks user data'
  },
  'CVE-2023-29008': {
    name: 'SvelteKit CSRF Bypass',
    type: 'CSRF',
    severity: SEVERITY.MEDIUM,
    cvss: 6.5,
    description: 'Content-Type case sensitivity bypasses CSRF protection'
  },
  'CVE-2024-23657': {
    name: 'Nuxt Devtools RCE',
    type: 'RCE',
    severity: SEVERITY.CRITICAL,
    cvss: 9.8,
    description: 'Path traversal in Nuxt Devtools leads to RCE'
  }
};

// Default settings
const DEFAULT_SETTINGS = {
  autoScanEnabled: false,
  scanMode: 'active',
  scanDepth: 'standard',
  scanDelay: 3000,
  notificationsEnabled: true,
  discordWebhookEnabled: false,
  discordWebhookUrl: '',
  proxyEnabled: false,
  proxyHost: '127.0.0.1',
  proxyPort: 8080,
  skipPaymentEndpoints: true,
  requireConfirmation: true,
  maxRequestsPerSecond: 5,
  saveHistory: true,
  maxHistoryItems: 1000
};

describe('Constants', () => {

  describe('Severity Levels', () => {
    test('defines all severity levels', () => {
      expect(SEVERITY.CRITICAL).toBe('CRITICAL');
      expect(SEVERITY.HIGH).toBe('HIGH');
      expect(SEVERITY.MEDIUM).toBe('MEDIUM');
      expect(SEVERITY.LOW).toBe('LOW');
      expect(SEVERITY.INFO).toBe('INFO');
    });

    test('has colors for all severity levels', () => {
      expect(SEVERITY_COLORS.CRITICAL).toBeDefined();
      expect(SEVERITY_COLORS.HIGH).toBeDefined();
      expect(SEVERITY_COLORS.MEDIUM).toBeDefined();
      expect(SEVERITY_COLORS.LOW).toBeDefined();
      expect(SEVERITY_COLORS.INFO).toBeDefined();
    });

    test('colors are valid hex codes', () => {
      const hexPattern = /^#[0-9a-f]{6}$/i;
      Object.values(SEVERITY_COLORS).forEach(color => {
        expect(hexPattern.test(color)).toBe(true);
      });
    });
  });

  describe('CVE Database', () => {
    test('contains React2Shell CVE', () => {
      const cve = CVE_DATABASE['CVE-2025-55182'];
      expect(cve).toBeDefined();
      expect(cve.name).toBe('React2Shell');
      expect(cve.severity).toBe(SEVERITY.CRITICAL);
      expect(cve.cvss).toBe(10.0);
    });

    test('contains Next.js Middleware Bypass CVE', () => {
      const cve = CVE_DATABASE['CVE-2025-29927'];
      expect(cve).toBeDefined();
      expect(cve.name).toBe('Next.js Middleware Bypass');
      expect(cve.severity).toBe(SEVERITY.CRITICAL);
    });

    test('contains Angular SSR Race Condition CVE', () => {
      const cve = CVE_DATABASE['CVE-2025-59052'];
      expect(cve).toBeDefined();
      expect(cve.severity).toBe(SEVERITY.HIGH);
    });

    test('contains SvelteKit CSRF CVE', () => {
      const cve = CVE_DATABASE['CVE-2023-29008'];
      expect(cve).toBeDefined();
      expect(cve.severity).toBe(SEVERITY.MEDIUM);
    });

    test('contains Nuxt Devtools RCE CVE', () => {
      const cve = CVE_DATABASE['CVE-2024-23657'];
      expect(cve).toBeDefined();
      expect(cve.severity).toBe(SEVERITY.CRITICAL);
    });

    test('all CVEs have required fields', () => {
      Object.entries(CVE_DATABASE).forEach(([id, cve]) => {
        expect(cve.name).toBeDefined();
        expect(cve.type).toBeDefined();
        expect(cve.severity).toBeDefined();
        expect(cve.description).toBeDefined();
      });
    });

    test('all CVEs have valid severity', () => {
      const validSeverities = Object.values(SEVERITY);
      Object.values(CVE_DATABASE).forEach(cve => {
        expect(validSeverities).toContain(cve.severity);
      });
    });

    test('all CVEs have valid CVSS scores', () => {
      Object.values(CVE_DATABASE).forEach(cve => {
        if (cve.cvss !== undefined) {
          expect(cve.cvss).toBeGreaterThanOrEqual(0);
          expect(cve.cvss).toBeLessThanOrEqual(10);
        }
      });
    });
  });

  describe('Default Settings', () => {
    test('has auto scan disabled by default', () => {
      expect(DEFAULT_SETTINGS.autoScanEnabled).toBe(false);
    });

    test('has active scan mode by default', () => {
      expect(DEFAULT_SETTINGS.scanMode).toBe('active');
    });

    test('has standard scan depth by default', () => {
      expect(DEFAULT_SETTINGS.scanDepth).toBe('standard');
    });

    test('has notifications enabled', () => {
      expect(DEFAULT_SETTINGS.notificationsEnabled).toBe(true);
    });

    test('has Discord webhook disabled', () => {
      expect(DEFAULT_SETTINGS.discordWebhookEnabled).toBe(false);
    });

    test('has proxy disabled', () => {
      expect(DEFAULT_SETTINGS.proxyEnabled).toBe(false);
    });

    test('skips payment endpoints by default', () => {
      expect(DEFAULT_SETTINGS.skipPaymentEndpoints).toBe(true);
    });

    test('requires confirmation for exploits', () => {
      expect(DEFAULT_SETTINGS.requireConfirmation).toBe(true);
    });

    test('has sensible rate limit', () => {
      expect(DEFAULT_SETTINGS.maxRequestsPerSecond).toBe(5);
    });

    test('saves history by default', () => {
      expect(DEFAULT_SETTINGS.saveHistory).toBe(true);
    });
  });
});
