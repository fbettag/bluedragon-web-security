/**
 * BlueDragon Web Security - Generic Scanners
 * Cross-framework vulnerability scanners
 */

import { SEVERITY } from '../../shared/constants.js';
import { generateSafeId, isBlockedEndpoint } from '../../shared/safety-filters.js';

/**
 * Security Headers Scanner
 * Checks for missing or misconfigured security headers
 */
export async function securityHeadersScanner(context) {
  const { url } = context;
  const results = [];

  try {
    const response = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(5000)
    });

    const headers = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });

    // Check for missing security headers
    const requiredHeaders = [
      {
        name: 'content-security-policy',
        severity: SEVERITY.MEDIUM,
        description: 'Content-Security-Policy header missing. XSS protection weakened.'
      },
      {
        name: 'x-frame-options',
        severity: SEVERITY.LOW,
        description: 'X-Frame-Options header missing. Page may be vulnerable to clickjacking.'
      },
      {
        name: 'x-content-type-options',
        severity: SEVERITY.LOW,
        description: 'X-Content-Type-Options header missing. MIME sniffing attacks possible.'
      },
      {
        name: 'strict-transport-security',
        severity: SEVERITY.MEDIUM,
        description: 'Strict-Transport-Security header missing. HTTPS not enforced.',
        httpsOnly: true
      },
      {
        name: 'referrer-policy',
        severity: SEVERITY.LOW,
        description: 'Referrer-Policy header missing. May leak sensitive URL parameters.'
      }
    ];

    const isHttps = url.startsWith('https://');

    for (const header of requiredHeaders) {
      if (header.httpsOnly && !isHttps) continue;

      if (!headers[header.name]) {
        results.push({
          type: 'Header',
          name: `Missing ${header.name}`,
          severity: header.severity,
          description: header.description,
          url,
          header: header.name,
          remediation: `Add ${header.name} header to server response`
        });
      }
    }

    // Check for problematic header values
    if (headers['x-powered-by']) {
      results.push({
        type: 'Header',
        name: 'X-Powered-By Header Exposed',
        severity: SEVERITY.INFO,
        description: `Server technology exposed: ${headers['x-powered-by']}`,
        url,
        header: 'x-powered-by',
        value: headers['x-powered-by'],
        remediation: 'Remove X-Powered-By header to reduce information disclosure'
      });
    }

    if (headers['server'] && !headers['server'].includes('cloudflare')) {
      results.push({
        type: 'Header',
        name: 'Server Header Exposed',
        severity: SEVERITY.INFO,
        description: `Server software exposed: ${headers['server']}`,
        url,
        header: 'server',
        value: headers['server'],
        remediation: 'Consider removing or obfuscating Server header'
      });
    }

    // Check CSP if present
    if (headers['content-security-policy']) {
      const csp = headers['content-security-policy'];

      if (csp.includes("'unsafe-inline'")) {
        results.push({
          type: 'Header',
          name: 'CSP Allows unsafe-inline',
          severity: SEVERITY.MEDIUM,
          description: 'Content-Security-Policy allows unsafe-inline scripts. XSS protection weakened.',
          url,
          header: 'content-security-policy',
          value: csp.substring(0, 200)
        });
      }

      if (csp.includes("'unsafe-eval'")) {
        results.push({
          type: 'Header',
          name: 'CSP Allows unsafe-eval',
          severity: SEVERITY.MEDIUM,
          description: 'Content-Security-Policy allows eval(). Code injection risk increased.',
          url,
          header: 'content-security-policy',
          value: csp.substring(0, 200)
        });
      }
    }

  } catch (e) {
    // Request failed
  }

  return results;
}

/**
 * Generic CSRF Scanner
 * Checks for CSRF vulnerabilities in forms and endpoints
 */
export async function csrfScanner(context) {
  const { url, document: doc, capturedRequests } = context;
  const results = [];

  if (!doc) return results;

  // Check forms for CSRF tokens
  const forms = doc.querySelectorAll('form[method="post"], form[method="POST"]');

  for (const form of forms) {
    const action = form.getAttribute('action') || url;

    // Skip blocked endpoints
    if (isBlockedEndpoint(action)) continue;

    // Look for CSRF token
    const csrfInputs = form.querySelectorAll(
      'input[name*="csrf"], input[name*="token"], input[name*="_token"], ' +
      'input[name*="authenticity"], input[name*="xsrf"]'
    );

    if (csrfInputs.length === 0) {
      results.push({
        type: 'CSRF',
        name: 'Form Without CSRF Token',
        severity: SEVERITY.MEDIUM,
        description: 'POST form found without apparent CSRF token.',
        url: action,
        formAction: action,
        formMethod: 'POST',
        fields: getFormFieldNames(form),
        note: 'Verify if alternative CSRF protection is in place (SameSite cookies, Origin checking)'
      });
    }
  }

  // Check AJAX endpoints without CSRF headers
  const postRequests = capturedRequests?.filter(r =>
    r.method === 'POST' &&
    !r.url.includes('analytics') &&
    !isBlockedEndpoint(r.url)
  ) || [];

  for (const req of postRequests.slice(0, 5)) {
    const headers = req.headers || {};
    const hasCSRFHeader =
      headers['x-csrf-token'] ||
      headers['x-xsrf-token'] ||
      headers['x-requested-with'];

    if (!hasCSRFHeader) {
      results.push({
        type: 'CSRF',
        name: 'AJAX Request Without CSRF Header',
        severity: SEVERITY.LOW,
        description: 'POST request without CSRF header detected.',
        url: req.url,
        method: 'POST',
        note: 'Request may rely on SameSite cookies or Origin header for CSRF protection'
      });
    }
  }

  return results;
}

/**
 * Get form field names
 */
function getFormFieldNames(form) {
  const fields = [];
  const inputs = form.querySelectorAll('input, select, textarea');

  for (const input of inputs) {
    if (input.name && input.type !== 'hidden') {
      fields.push(input.name);
    }
  }

  return fields.slice(0, 10);
}

/**
 * Generic SSRF Scanner
 * Checks for SSRF via various vectors
 */
export async function ssrfScanner(context) {
  const { url, document: doc, settings } = context;
  const results = [];

  // Check for URL parameters that might be SSRF vectors
  const currentUrl = new URL(url);
  const ssrfParams = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'target', 'proxy', 'fetch'];

  for (const param of ssrfParams) {
    if (currentUrl.searchParams.has(param)) {
      results.push({
        type: 'SSRF',
        name: 'Potential SSRF Parameter',
        severity: SEVERITY.MEDIUM,
        description: `URL parameter '${param}' may be vulnerable to SSRF.`,
        url,
        parameter: param,
        value: currentUrl.searchParams.get(param),
        requiresProbe: true,
        testVector: `Set ${param}=http://169.254.169.254/latest/meta-data/`
      });
    }
  }

  // Check forms for URL inputs
  if (doc) {
    const urlInputs = doc.querySelectorAll(
      'input[type="url"], input[name*="url"], input[name*="link"], input[name*="uri"]'
    );

    for (const input of urlInputs) {
      const form = input.closest('form');
      if (form && !isBlockedEndpoint(form.action || url)) {
        results.push({
          type: 'SSRF',
          name: 'URL Input Field',
          severity: SEVERITY.LOW,
          description: 'Form accepts URL input. May be vulnerable to SSRF.',
          url: form.action || url,
          inputName: input.name,
          requiresProbe: true
        });
      }
    }
  }

  return results;
}

/**
 * Header Injection Scanner
 * Checks for header injection vulnerabilities
 */
export async function headerInjectionScanner(context) {
  const { url, settings } = context;
  const results = [];

  if (settings?.scanMode !== 'active') {
    return results;
  }

  const probeId = generateSafeId();

  // Test Host header injection
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Host': `${probeId}.test.invalid`,
        'X-Forwarded-Host': `${probeId}.test.invalid`,
        'X-Forwarded-For': '127.0.0.1',
        'X-BlueDragon-Probe': probeId
      },
      signal: AbortSignal.timeout(5000)
    });

    const body = await response.text();

    // Check if our injected host appears in response
    if (body.includes(probeId)) {
      results.push({
        type: 'Header Injection',
        name: 'Host Header Reflected',
        severity: SEVERITY.MEDIUM,
        description: 'Injected Host header reflected in response. May indicate cache poisoning or SSRF vulnerability.',
        url,
        probeId,
        evidence: 'Probe ID found in response body'
      });
    }

    // Check response headers for reflection
    const locationHeader = response.headers.get('location');
    if (locationHeader?.includes(probeId)) {
      results.push({
        type: 'Header Injection',
        name: 'Host Header in Redirect',
        severity: SEVERITY.HIGH,
        description: 'Injected Host header appears in redirect Location. Open redirect via header injection.',
        url,
        probeId,
        redirectLocation: locationHeader
      });
    }
  } catch (e) {
    // Request failed
  }

  return results;
}

export default {
  securityHeadersScanner,
  csrfScanner,
  ssrfScanner,
  headerInjectionScanner
};
