/**
 * BlueDragon Web Security - Angular Scanners
 * Vulnerability scanners for Angular ecosystem
 */

import { SEVERITY } from '../../shared/constants.js';
import { generateSafeId } from '../../shared/safety-filters.js';

/**
 * Race Condition Scanner (CVE-2025-59052)
 * Detects potential Global Platform Injector race condition
 */
export async function raceConditionScanner(context) {
  const { framework, url } = context;
  const results = [];

  // Only applicable to Angular SSR
  if (framework?.framework !== 'Angular' || !framework.isSSR) {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkRaceConditionVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'Race Condition',
      name: 'Angular SSR Race Condition (CVE-2025-59052)',
      severity: SEVERITY.HIGH,
      cvss: 7.1,
      cve: 'CVE-2025-59052',
      description: `Angular ${version} SSR is vulnerable to race condition that may leak user data between requests.`,
      url,
      framework: framework.framework,
      version,
      isSSR: true,
      requiresProbe: false, // Can't safely probe race conditions
      exploitConditions: 'High-concurrency traffic required',
      remediation: 'Upgrade to Angular 21.0.0-next.4 or later',
      note: 'This vulnerability requires concurrent requests to exploit. Automated verification not recommended.'
    });
  } else if (isVulnerable === 'unknown' && framework.isSSR) {
    results.push({
      type: 'Race Condition',
      name: 'Angular SSR Race Condition - Potential',
      severity: SEVERITY.MEDIUM,
      cve: 'CVE-2025-59052',
      description: 'Angular SSR detected but version unknown. May be vulnerable to race condition.',
      url,
      framework: framework.framework,
      isSSR: true,
      note: 'Manual version verification recommended.'
    });
  }

  return results;
}

/**
 * Check if version is vulnerable to race condition
 */
function checkRaceConditionVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 16.x through 21.0.0-next.3
  if (parts[0] >= 16 && parts[0] <= 20) {
    return true;
  }

  if (parts[0] === 21 && parts[1] === 0 && parts[2] === 0) {
    // Check for next.x suffix
    if (version.includes('next')) {
      const nextMatch = version.match(/next\.(\d+)/);
      if (nextMatch && parseInt(nextMatch[1], 10) <= 3) {
        return true;
      }
    }
  }

  return false;
}

/**
 * URL SSRF Scanner (CVE-2025-62427)
 * Detects SSRF via double-slash URL injection
 */
export async function urlSSRFScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to Angular SSR
  if (framework?.framework !== 'Angular' || !framework.isSSR) {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkURLSSRFVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'SSRF',
      name: 'Angular SSR URL SSRF (CVE-2025-62427)',
      severity: SEVERITY.HIGH,
      cvss: 8.7,
      cve: 'CVE-2025-62427',
      description: `Angular ${version} SSR is vulnerable to SSRF via double-slash URL injection.`,
      url,
      framework: framework.framework,
      version,
      isSSR: true,
      requiresProbe: true,
      testVector: 'GET //attacker.com/path HTTP/1.1',
      remediation: 'Upgrade to patched Angular version'
    });
  }

  // Active probing
  if (settings?.scanMode === 'active') {
    const probeResult = await probeURLSSRF(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to URL SSRF
 */
function checkURLSSRFVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 17.x through 21.x
  if (parts[0] >= 17 && parts[0] <= 21) {
    return true;
  }

  return false;
}

/**
 * Probe URL SSRF vulnerability
 */
async function probeURLSSRF(url, context) {
  const collaboratorUrl = context.settings?.collaboratorUrl;
  const collaboratorId = generateSafeId();

  try {
    const baseUrl = new URL(url);

    // Craft double-slash injection
    const probeUrl = `//${collaboratorId}.${collaboratorUrl || 'httpbin.org'}/ssrf-test`;

    const response = await fetch(`${baseUrl.origin}${probeUrl}`, {
      method: 'GET',
      headers: {
        'X-BlueDragon-Probe': collaboratorId
      },
      signal: AbortSignal.timeout(5000),
      redirect: 'manual' // Don't follow redirects
    });

    // Check if server attempted to resolve the attacker URL
    // This would require collaborator callback verification

    if (response.status === 200 || response.status === 302) {
      return {
        type: 'SSRF',
        name: 'Angular SSR URL SSRF - Probe Result',
        severity: SEVERITY.INFO,
        description: 'SSRF probe sent. Check collaborator for callback.',
        url: probeUrl,
        collaboratorId,
        responseStatus: response.status,
        note: 'Verify with collaborator callback or Burp Suite'
      };
    }
  } catch (e) {
    // Request failed - might not be vulnerable
  }

  return null;
}

/**
 * XSRF Token Leakage Scanner (CVE-2025-66035)
 * Detects XSRF token exposure via state transfer in SSR apps
 */
export async function xsrfLeakScanner(context) {
  const { framework, url, document: doc } = context;
  const results = [];

  // Only applicable to Angular SSR
  if (framework?.framework !== 'Angular' || !framework.isSSR) {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkXSRFLeakVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'INFO_LEAK',
      name: 'Angular XSRF Token Leakage (CVE-2025-66035)',
      severity: SEVERITY.MEDIUM,
      cvss: 5.3,
      cve: 'CVE-2025-66035',
      description: `Angular ${version} SSR may expose XSRF tokens via server state transfer`,
      url,
      framework: framework.framework,
      version,
      isSSR: true,
      requiresProbe: true,
      note: 'Check HTML source for XSRF token in __NGSSSR_STATE__',
      remediation: 'Upgrade to Angular 19.2.1+ or 19.3.0-rc.0+'
    });
  }

  // Check for XSRF token in HTML
  if (doc) {
    const html = doc.documentElement.innerHTML;
    const xsrfPatterns = [
      /__NGSSSR_STATE__.*XSRF-TOKEN/i,
      /XSRF-TOKEN.*=.*[a-zA-Z0-9+/=]{20,}/,
      /xsrf.*token.*[a-zA-Z0-9+/=]{20,}/i
    ];

    for (const pattern of xsrfPatterns) {
      if (pattern.test(html)) {
        results.push({
          type: 'INFO_LEAK',
          name: 'XSRF Token Found in HTML',
          severity: SEVERITY.MEDIUM,
          description: 'XSRF token detected in HTML source. May be exploitable.',
          url,
          framework: framework.framework,
          exploitable: true,
          note: 'Token may be used for CSRF attacks against other users'
        });
        break;
      }
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to XSRF leak
 */
function checkXSRFLeakVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 18.x through 19.2.0
  if (parts[0] === 18) return true;
  if (parts[0] === 19 && (parts[1] < 2 || (parts[1] === 2 && parts[2] === 0))) return true;

  return false;
}

/**
 * Angular Stored XSS Scanner (CVE-2025-66412)
 * Detects XSS via SSR hydration state manipulation
 */
export async function angularXSSScanner(context) {
  const { framework, url, document: doc, settings } = context;
  const results = [];

  // Only applicable to Angular SSR
  if (framework?.framework !== 'Angular' || !framework.isSSR) {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkAngularXSSVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'XSS',
      name: 'Angular SSR Stored XSS (CVE-2025-66412)',
      severity: SEVERITY.MEDIUM,
      cvss: 6.1,
      cve: 'CVE-2025-66412',
      description: `Angular ${version} SSR may be vulnerable to stored XSS via hydration state`,
      url,
      framework: framework.framework,
      version,
      isSSR: true,
      requiresProbe: true,
      testVector: 'Inject script via server-rendered content that persists in hydration state',
      remediation: 'Upgrade to Angular 19.2.1+ or 19.3.0-rc.0+'
    });
  }

  // Check for hydration state in HTML that might contain user input
  if (doc) {
    const html = doc.documentElement.innerHTML;
    const hydrationPatterns = [
      /__NGSSSR_STATE__/,
      /serverApp/,
      /ng-server-context/
    ];

    let hasHydration = false;
    for (const pattern of hydrationPatterns) {
      if (pattern.test(html)) {
        hasHydration = true;
        break;
      }
    }

    if (hasHydration) {
      results.push({
        type: 'XSS',
        name: 'Angular Hydration State Detected',
        severity: SEVERITY.LOW,
        description: 'Angular SSR hydration state found. Check for XSS via user-controlled content.',
        url,
        framework: framework.framework,
        note: 'Manually verify user input is properly sanitized in hydration state'
      });
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to Angular XSS
 */
function checkAngularXSSVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 18.x through 19.2.0
  if (parts[0] === 18) return true;
  if (parts[0] === 19 && (parts[1] < 2 || (parts[1] === 2 && parts[2] === 0))) return true;

  return false;
}

export default {
  raceConditionScanner,
  urlSSRFScanner,
  xsrfLeakScanner,
  angularXSSScanner
};
