/**
 * BlueDragon Web Security - SvelteKit Scanners
 * Vulnerability scanners for SvelteKit ecosystem
 */

import { SEVERITY } from '../../shared/constants.js';
import { generateSafeId } from '../../shared/safety-filters.js';

/**
 * CSRF Bypass Scanner (CVE-2023-29008)
 * Detects CSRF protection bypass via Content-Type case manipulation
 */
export async function csrfBypassScanner(context) {
  const { framework, url, capturedRequests, settings } = context;
  const results = [];

  // Only applicable to SvelteKit
  if (framework?.framework !== 'SvelteKit') {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkCSRFBypassVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'CSRF',
      name: 'SvelteKit CSRF Bypass (CVE-2023-29008)',
      severity: SEVERITY.MEDIUM,
      cvss: 6.5,
      cve: 'CVE-2023-29008',
      description: `SvelteKit ${version} CSRF protection can be bypassed with mixed-case Content-Type header.`,
      url,
      framework: framework.framework,
      version,
      requiresProbe: true,
      testVector: 'Content-Type: text/plaiN or application/x-www-form-URLencoded',
      remediation: 'Upgrade to SvelteKit 1.5.1 or later'
    });
  }

  // Active probing
  if (settings?.scanMode === 'active') {
    const probeResult = await probeCSRFBypass(url, capturedRequests, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to CSRF bypass
 */
function checkCSRFBypassVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 1.0.0 to 1.5.0
  if (parts[0] === 1 && parts[1] <= 5) {
    if (parts[1] < 5 || (parts[1] === 5 && parts[2] === 0)) {
      return true;
    }
  }

  return false;
}

/**
 * Probe CSRF bypass vulnerability
 */
async function probeCSRFBypass(url, capturedRequests, context) {
  // Find a POST request to replay
  const postRequests = capturedRequests.filter(r =>
    r.method === 'POST' &&
    !r.url.includes('logout') &&
    !r.url.includes('login')
  );

  if (postRequests.length === 0) {
    // Try with form actions
    if (context.document) {
      const forms = context.document.querySelectorAll('form[method="post"]');
      if (forms.length > 0) {
        return {
          type: 'CSRF',
          name: 'CSRF Bypass - Forms Detected',
          severity: SEVERITY.INFO,
          description: `${forms.length} POST forms found. Manual CSRF bypass testing recommended.`,
          url,
          testVector: 'Change Content-Type to mixed case (text/plaiN)',
          note: 'Replay form submission with modified Content-Type header'
        };
      }
    }
    return null;
  }

  // Try first POST request with mixed-case Content-Type
  const targetRequest = postRequests[0];

  try {
    const probeId = generateSafeId();

    const response = await fetch(targetRequest.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plaiN',  // Mixed case bypass
        'X-BlueDragon-Probe': probeId
      },
      body: targetRequest.body || '',
      credentials: 'omit', // Don't send cookies (cross-origin test)
      signal: AbortSignal.timeout(5000)
    });

    // If we get a non-403/401 response, CSRF might be bypassed
    if (response.ok || response.status === 200 || response.status === 302) {
      return {
        type: 'CSRF',
        name: 'CSRF Bypass - Confirmed',
        severity: SEVERITY.MEDIUM,
        cvss: 6.5,
        cve: 'CVE-2023-29008',
        description: 'CSRF protection bypassed with mixed-case Content-Type.',
        url: targetRequest.url,
        probeResult: {
          status: response.status,
          contentType: 'text/plaiN',
          bypassed: true
        },
        remediation: 'Upgrade SvelteKit to 1.5.1+'
      };
    }
  } catch (e) {
    // Request failed
  }

  return null;
}

/**
 * Template Injection Scanner (CVE-2024-53262)
 * Detects potential XSS via error template injection
 */
export async function templateInjectionScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to SvelteKit
  if (framework?.framework !== 'SvelteKit') {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkTemplateInjectionVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'XSS',
      name: 'SvelteKit Template Injection (CVE-2024-53262)',
      severity: SEVERITY.MEDIUM,
      cvss: 6.1,
      cve: 'CVE-2024-53262',
      description: `SvelteKit ${version} error pages may be vulnerable to XSS via template injection.`,
      url,
      framework: framework.framework,
      version,
      requiresProbe: true,
      exploitConditions: 'Application must throw errors with user-controlled content',
      testVector: 'Cause error with payload in error message',
      remediation: 'Upgrade to SvelteKit 2.8.1 or later',
      note: 'Requires application to explicitly use user input in error messages'
    });
  }

  // Active probing
  if (settings?.scanMode === 'active') {
    const probeResult = await probeTemplateInjection(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to template injection
 */
function checkTemplateInjectionVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 2.0.0 to 2.8.0
  if (parts[0] === 2 && parts[1] <= 8) {
    return true;
  }

  return false;
}

/**
 * Probe template injection vulnerability
 */
async function probeTemplateInjection(url, context) {
  const probeId = generateSafeId();

  // Try to trigger an error with a safe XSS marker
  const testPayloads = [
    `<img src=x onerror=alert('${probeId}')>`,
    `{{constructor.constructor('alert("${probeId}")')()}}`,
    `%3Cscript%3Ealert('${probeId}')%3C/script%3E`
  ];

  for (const payload of testPayloads) {
    try {
      const testUrl = new URL(url);
      testUrl.searchParams.set('error', payload);

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });

      const body = await response.text();

      // Check if payload is reflected unescaped
      if (body.includes(payload) && !body.includes(encodeURIComponent(payload))) {
        return {
          type: 'XSS',
          name: 'Template Injection - Reflected',
          severity: SEVERITY.MEDIUM,
          description: 'XSS payload reflected in response. May be exploitable.',
          url: testUrl.toString(),
          probeId,
          payload: payload.substring(0, 50),
          note: 'Payload appears to be reflected without encoding'
        };
      }
    } catch (e) {
      // Request failed
    }
  }

  return null;
}

/**
 * SearchParams XSS Scanner (CVE-2025-32388)
 * Detects XSS via URL searchParams passed to goto()
 */
export async function searchParamsXSSScanner(context) {
  const { framework, url, document: doc, settings } = context;
  const results = [];

  // Only applicable to SvelteKit
  if (framework?.framework !== 'SvelteKit') {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkSearchParamsXSSVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'XSS',
      name: 'SvelteKit searchParams XSS (CVE-2025-32388)',
      severity: SEVERITY.MEDIUM,
      cvss: 6.1,
      cve: 'CVE-2025-32388',
      description: `SvelteKit ${version} is vulnerable to XSS via URL searchParams passed to goto()`,
      url,
      framework: framework.framework,
      version,
      requiresProbe: true,
      testVector: 'Inject XSS payload in URL search params that are passed to goto() navigation',
      remediation: 'Upgrade to SvelteKit 2.20.7 or later',
      note: 'Requires application to use searchParams with goto() function'
    });
  }

  // Look for goto() usage patterns in scripts
  if (doc) {
    const html = doc.documentElement.innerHTML;
    const gotoPatterns = [
      /goto\s*\([^)]*searchParams/i,
      /goto\s*\([^)]*\$page\.url/i,
      /goto\s*\([^)]*url\.searchParams/i
    ];

    for (const pattern of gotoPatterns) {
      if (pattern.test(html)) {
        results.push({
          type: 'XSS',
          name: 'SearchParams Usage Detected',
          severity: SEVERITY.LOW,
          description: 'goto() with searchParams detected. May be vulnerable to CVE-2025-32388.',
          url,
          framework: framework.framework,
          note: 'Manually verify searchParams are not used unsanitized'
        });
        break;
      }
    }
  }

  // Active probing
  if (settings?.scanMode === 'active') {
    const probeResult = await probeSearchParamsXSS(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to searchParams XSS
 */
function checkSearchParamsXSSVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 2.0.0 to 2.20.6
  if (parts[0] === 2 && (parts[1] < 20 || (parts[1] === 20 && parts[2] <= 6))) {
    return true;
  }

  return false;
}

/**
 * Probe searchParams XSS vulnerability
 */
async function probeSearchParamsXSS(url, context) {
  const probeId = generateSafeId();

  // Test payloads for searchParams XSS
  const xssPayloads = [
    `javascript:alert('${probeId}')`,
    `data:text/html,<script>alert('${probeId}')</script>`,
    `//evil.com/xss?${probeId}`
  ];

  for (const payload of xssPayloads) {
    try {
      const testUrl = new URL(url);
      testUrl.searchParams.set('redirect', payload);
      testUrl.searchParams.set('next', payload);
      testUrl.searchParams.set('url', payload);

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });

      // Check Location header for XSS payload
      const location = response.headers.get('location') || '';
      if (location.includes('javascript:') || location.includes('data:text/html')) {
        return {
          type: 'XSS',
          name: 'SearchParams XSS - Open Redirect to XSS',
          severity: SEVERITY.MEDIUM,
          cve: 'CVE-2025-32388',
          description: 'XSS payload reflected in redirect Location header.',
          url: testUrl.toString(),
          probeId,
          location,
          exploitable: true
        };
      }

      // Check response body
      const body = await response.text();
      if (body.includes(payload) && (body.includes('javascript:') || body.includes('data:text/html'))) {
        return {
          type: 'XSS',
          name: 'SearchParams XSS - Reflected',
          severity: SEVERITY.MEDIUM,
          cve: 'CVE-2025-32388',
          description: 'XSS payload reflected in response body.',
          url: testUrl.toString(),
          probeId,
          exploitable: true
        };
      }
    } catch (e) {
      // Request failed
    }
  }

  return null;
}

export default {
  csrfBypassScanner,
  templateInjectionScanner,
  searchParamsXSSScanner
};
