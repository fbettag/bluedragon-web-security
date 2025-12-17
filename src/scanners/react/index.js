/**
 * BlueDragon Web Security - React/Next.js Scanners
 * Vulnerability scanners for React ecosystem
 */

import { SEVERITY } from '../../shared/constants.js';
import { generateSafeId } from '../../shared/safety-filters.js';

/**
 * React2Shell Scanner (CVE-2025-55182)
 * Detects and safely probes for Flight protocol RCE
 */
export async function react2shellScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to Next.js with RSC
  if (!framework?.hasRSC && framework?.framework !== 'Next.js') {
    return results;
  }

  // Check version first (passive)
  const version = framework.version;
  const isVulnerableVersion = checkVulnerableVersion(version);

  if (isVulnerableVersion === true) {
    results.push({
      type: 'RCE',
      name: 'React2Shell (CVE-2025-55182)',
      severity: SEVERITY.CRITICAL,
      cvss: 10.0,
      cve: 'CVE-2025-55182',
      description: `Next.js ${version} with RSC is vulnerable to unauthenticated RCE via Flight protocol deserialization`,
      url,
      framework: framework.framework,
      version,
      exploitable: true,
      requiresProbe: true,
      indicators: framework.indicators || [],
      remediation: 'Upgrade to Next.js 15.0.5+, 15.1.9+, or 16.0.7+',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2025-55182'
      ]
    });
  } else if (isVulnerableVersion === 'unknown' && framework.hasRSC) {
    results.push({
      type: 'RCE',
      name: 'React2Shell (CVE-2025-55182) - Potential',
      severity: SEVERITY.HIGH,
      cve: 'CVE-2025-55182',
      description: 'RSC detected but version unknown. Application may be vulnerable to React2Shell.',
      url,
      framework: framework.framework,
      requiresProbe: true,
      note: 'Version fingerprinting failed. Manual verification recommended.'
    });
  }

  // If active probing is enabled, send safe probe
  if (settings?.scanMode === 'active' && framework.hasRSC) {
    const probeResult = await probeFlightProtocol(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to React2Shell
 */
function checkVulnerableVersion(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 15.0.0-15.0.4, 16.0.0-16.0.6
  if (parts[0] === 15) {
    if (parts[1] === 0 && parts[2] <= 4) return true;
    if (parts[1] === 1 && parts[2] <= 8) return true;
  }

  if (parts[0] === 16) {
    if (parts[1] === 0 && parts[2] <= 6) return true;
  }

  return false;
}

/**
 * Safely probe Flight protocol
 */
async function probeFlightProtocol(url, context) {
  // This is a non-destructive probe that checks for Flight protocol behavior
  // We send a malformed but safe payload that triggers a specific error

  try {
    const probeUrl = new URL(url);

    // Try to find RSC endpoint
    const response = await fetch(probeUrl.toString(), {
      method: 'POST',
      headers: {
        'RSC': '1',
        'Content-Type': 'text/x-component',
        'X-BlueDragon-Probe': generateSafeId()
      },
      body: '0:{"test":true}', // Safe Flight-like payload
      signal: AbortSignal.timeout(5000)
    });

    // Check response for Flight protocol indicators
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('text/x-component') || response.status === 500) {
      return {
        type: 'RCE',
        name: 'Flight Protocol Active',
        severity: SEVERITY.MEDIUM,
        description: 'Flight protocol endpoint responds to RSC requests. Further investigation recommended.',
        url,
        probeResult: {
          status: response.status,
          contentType,
          flightActive: true
        },
        note: 'This confirms RSC is active. Check version for CVE-2025-55182.'
      };
    }
  } catch (e) {
    // Timeout or error - endpoint may not support Flight
  }

  return null;
}

/**
 * Server Action SSRF Scanner (CVE-2024-34351)
 * Detects SSRF via Host header in Server Actions
 */
export async function serverActionSSRFScanner(context) {
  const { framework, url, capturedRequests, settings } = context;
  const results = [];

  // Look for Server Actions
  const serverActions = findServerActions(context);

  if (serverActions.length === 0) {
    return results;
  }

  // Report potential vulnerability
  results.push({
    type: 'SSRF',
    name: 'Server Action SSRF (CVE-2024-34351)',
    severity: SEVERITY.HIGH,
    cvss: 7.5,
    cve: 'CVE-2024-34351',
    description: 'Server Actions detected. Host header injection may lead to SSRF in self-hosted deployments.',
    url,
    framework: framework?.framework,
    endpoints: serverActions,
    requiresProbe: true,
    testVector: 'Modify Host header in Server Action POST request',
    note: 'Not exploitable on Vercel-hosted apps due to edge layer.',
    remediation: 'Upgrade Next.js or configure trusted hosts'
  });

  // If active probing with collaborator
  if (settings?.scanMode === 'active' && settings?.collaboratorUrl) {
    const ssrfResult = await probeServerActionSSRF(serverActions, context);
    if (ssrfResult) {
      results.push(ssrfResult);
    }
  }

  return results;
}

/**
 * Find Server Action endpoints
 */
function findServerActions(context) {
  const actions = [];

  // Check captured requests
  for (const req of context.capturedRequests || []) {
    if (req.headers?.['next-action']) {
      actions.push({
        url: req.url,
        method: req.method,
        actionId: req.headers['next-action']
      });
    }
  }

  // Check document for form actions
  if (context.document) {
    const forms = context.document.querySelectorAll('form[action]');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (action?.includes('$ACTION')) {
        actions.push({
          url: action,
          method: 'POST',
          type: 'form'
        });
      }
    }
  }

  return actions;
}

/**
 * Probe Server Action SSRF with collaborator
 */
async function probeServerActionSSRF(actions, context) {
  if (actions.length === 0 || !context.settings?.collaboratorUrl) {
    return null;
  }

  const collaboratorId = generateSafeId();
  const collaboratorUrl = `${collaboratorId}.${context.settings.collaboratorUrl}`;

  // Try first action
  const action = actions[0];

  try {
    await fetch(action.url, {
      method: 'POST',
      headers: {
        'Host': collaboratorUrl,
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-BlueDragon-Probe': collaboratorId
      },
      body: '',
      credentials: 'omit',
      signal: AbortSignal.timeout(5000)
    });

    // Result will come via collaborator callback
    return {
      type: 'SSRF',
      name: 'Server Action SSRF - Probe Sent',
      severity: SEVERITY.INFO,
      description: `SSRF probe sent with collaborator ID: ${collaboratorId}`,
      url: action.url,
      collaboratorId,
      note: 'Check collaborator for incoming requests'
    };
  } catch (e) {
    return null;
  }
}

/**
 * Image Optimization DoS Scanner (CVE-2024-47831)
 */
export async function imageDoSScanner(context) {
  const { framework, url } = context;
  const results = [];

  if (framework?.framework !== 'Next.js') {
    return results;
  }

  // Check for image optimization endpoint
  try {
    const imageUrl = new URL('/_next/image', url);
    imageUrl.searchParams.set('url', 'https://example.com/test.png');
    imageUrl.searchParams.set('w', '64');
    imageUrl.searchParams.set('q', '75');

    const response = await fetch(imageUrl.toString(), {
      method: 'HEAD',
      signal: AbortSignal.timeout(5000)
    });

    if (response.status !== 404) {
      // Check if external URLs are allowed
      const externalTest = new URL('/_next/image', url);
      externalTest.searchParams.set('url', 'https://httpbin.org/image/png');
      externalTest.searchParams.set('w', '64');
      externalTest.searchParams.set('q', '75');

      const externalResponse = await fetch(externalTest.toString(), {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });

      if (externalResponse.ok) {
        results.push({
          type: 'DoS',
          name: 'Image Optimization External URL (CVE-2024-47831)',
          severity: SEVERITY.MEDIUM,
          cvss: 5.3,
          cve: 'CVE-2024-47831',
          description: 'Image optimization endpoint accepts external URLs. May be vulnerable to resource exhaustion.',
          url: imageUrl.toString(),
          endpoint: '/_next/image',
          externalUrls: true,
          remediation: 'Configure images.domains in next.config.js to allowlist specific domains'
        });
      } else {
        results.push({
          type: 'Configuration',
          name: 'Image Optimization Endpoint',
          severity: SEVERITY.LOW,
          description: 'Image optimization endpoint exists but external URLs appear restricted.',
          url: imageUrl.toString(),
          endpoint: '/_next/image'
        });
      }
    }
  } catch (e) {
    // Endpoint not accessible
  }

  return results;
}

/**
 * Next.js Middleware Authorization Bypass Scanner (CVE-2025-29927)
 * Detects vulnerability to x-middleware-subrequest header bypass
 */
export async function middlewareBypassScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  if (framework?.framework !== 'Next.js') {
    return results;
  }

  // Check version first
  const version = framework.version;
  const isVulnerableVersion = checkMiddlewareBypassVersion(version);

  if (isVulnerableVersion === true) {
    results.push({
      type: 'AUTH_BYPASS',
      name: 'Next.js Middleware Authorization Bypass (CVE-2025-29927)',
      severity: SEVERITY.CRITICAL,
      cvss: 9.1,
      cve: 'CVE-2025-29927',
      description: `Next.js ${version} is vulnerable to middleware authorization bypass via x-middleware-subrequest header`,
      url,
      framework: framework.framework,
      version,
      exploitable: true,
      requiresProbe: true,
      testVector: 'Add x-middleware-subrequest: 1 header to bypass middleware checks',
      indicators: framework.indicators || [],
      remediation: 'Upgrade to Next.js 12.3.5+, 13.5.9+, 14.2.25+, or 15.2.3+',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
        'https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw'
      ]
    });
  }

  // Active probe if enabled
  if (settings?.scanMode === 'active') {
    const probeResult = await probeMiddlewareBypass(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to middleware bypass
 */
function checkMiddlewareBypassVersion(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 11.1.4-12.3.4, 13.0.0-13.5.8, 14.0.0-14.2.24, 15.0.0-15.2.2
  if (parts[0] === 11 && parts[1] >= 1) return true;
  if (parts[0] === 12 && (parts[1] < 3 || (parts[1] === 3 && parts[2] <= 4))) return true;
  if (parts[0] === 13 && (parts[1] < 5 || (parts[1] === 5 && parts[2] <= 8))) return true;
  if (parts[0] === 14 && (parts[1] < 2 || (parts[1] === 2 && parts[2] <= 24))) return true;
  if (parts[0] === 15 && (parts[1] < 2 || (parts[1] === 2 && parts[2] <= 2))) return true;

  return false;
}

/**
 * Probe for middleware bypass
 */
async function probeMiddlewareBypass(url, context) {
  try {
    // Try common protected paths
    const protectedPaths = ['/admin', '/dashboard', '/api/admin', '/settings', '/profile'];
    const probeId = generateSafeId();

    for (const path of protectedPaths) {
      const testUrl = new URL(path, url);

      // Request without bypass header
      const normalResponse = await fetch(testUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });

      // Request with bypass header
      const bypassResponse = await fetch(testUrl.toString(), {
        method: 'GET',
        headers: {
          'x-middleware-subrequest': '1',
          'X-BlueDragon-Probe': probeId
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });

      // Check if bypass worked
      if (normalResponse.status !== bypassResponse.status) {
        // Different status indicates potential bypass
        if ((normalResponse.status === 302 || normalResponse.status === 401 || normalResponse.status === 403) &&
            (bypassResponse.status === 200 || bypassResponse.status === 304)) {
          return {
            type: 'AUTH_BYPASS',
            name: 'Middleware Bypass Confirmed',
            severity: SEVERITY.CRITICAL,
            cve: 'CVE-2025-29927',
            description: `Middleware authorization bypass confirmed on ${path}`,
            url: testUrl.toString(),
            probeResult: {
              normalStatus: normalResponse.status,
              bypassStatus: bypassResponse.status,
              path
            },
            exploitable: true
          };
        }
      }
    }
  } catch (e) {
    // Probe failed
  }

  return null;
}

/**
 * React Source Code Exposure Scanner (CVE-2025-55183)
 * Detects potential server source code exposure via RSC responses
 */
export async function sourceCodeExposureScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to RSC frameworks
  if (!framework?.hasRSC) {
    return results;
  }

  const version = framework.version;
  const isVulnerableVersion = checkSourceExposureVersion(version);

  if (isVulnerableVersion === true || isVulnerableVersion === 'unknown') {
    results.push({
      type: 'SOURCE_EXPOSURE',
      name: 'React Source Code Exposure (CVE-2025-55183)',
      severity: SEVERITY.MEDIUM,
      cvss: 5.3,
      cve: 'CVE-2025-55183',
      description: 'Server source code may be exposed via RSC Flight protocol responses',
      url,
      framework: framework.framework,
      version,
      requiresProbe: true,
      note: 'Check RSC responses for server-side code leakage',
      remediation: 'Upgrade React to 19.1.1+ or Next.js to patched version'
    });
  }

  return results;
}

/**
 * Check if version is vulnerable to source code exposure
 */
function checkSourceExposureVersion(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // React 19.0.0-19.1.0
  if (parts[0] === 19 && parts[1] <= 1 && parts[2] === 0) return true;

  return false;
}

/**
 * React DoS Scanner (CVE-2025-55184 & CVE-2025-67779)
 * Detects DoS vulnerability via malformed RSC payloads
 */
export async function reactDoSScanner(context) {
  const { framework, url } = context;
  const results = [];

  // Only applicable to RSC frameworks
  if (!framework?.hasRSC) {
    return results;
  }

  const version = framework.version;

  // CVE-2025-55184: React 19.0.0-19.1.0
  if (checkReactDoSVersion(version, '55184') === true) {
    results.push({
      type: 'DoS',
      name: 'React DoS via Infinite Loop (CVE-2025-55184)',
      severity: SEVERITY.HIGH,
      cvss: 7.5,
      cve: 'CVE-2025-55184',
      description: 'Malformed RSC payload can cause infinite loop and server hang',
      url,
      framework: framework.framework,
      version,
      note: 'Server can be crashed with crafted Flight protocol payload',
      remediation: 'Upgrade React to 19.1.1+'
    });
  }

  // CVE-2025-67779: React 19.1.0 (incomplete fix)
  if (checkReactDoSVersion(version, '67779') === true) {
    results.push({
      type: 'DoS',
      name: 'React DoS Incomplete Fix (CVE-2025-67779)',
      severity: SEVERITY.HIGH,
      cvss: 7.5,
      cve: 'CVE-2025-67779',
      description: 'Incomplete fix for CVE-2025-55184, still exploitable via different payload',
      url,
      framework: framework.framework,
      version,
      note: 'React 19.1.0 patch was incomplete',
      remediation: 'Upgrade React to latest patched version'
    });
  }

  return results;
}

/**
 * Check React DoS vulnerability by version
 */
function checkReactDoSVersion(version, cve) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  if (cve === '55184') {
    // React 19.0.0-19.1.0
    if (parts[0] === 19 && parts[1] <= 1 && parts[2] === 0) return true;
  }

  if (cve === '67779') {
    // React 19.1.0 specifically
    if (parts[0] === 19 && parts[1] === 1 && parts[2] === 0) return true;
  }

  return false;
}

export default {
  react2shellScanner,
  serverActionSSRFScanner,
  imageDoSScanner,
  middlewareBypassScanner,
  sourceCodeExposureScanner,
  reactDoSScanner
};
