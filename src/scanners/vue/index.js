/**
 * BlueDragon Web Security - Vue/Nuxt Scanners
 * Vulnerability scanners for Vue.js ecosystem
 */

import { SEVERITY } from '../../shared/constants.js';
import { generateSafeId } from '../../shared/safety-filters.js';

/**
 * Dev Server Injection Scanner (CVE-2023-3224)
 * Detects Nuxt development server code injection
 */
export async function devInjectionScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to Nuxt
  if (framework?.framework !== 'Nuxt') {
    return results;
  }

  // Check if dev mode is detected
  if (!framework.isDev) {
    return results;
  }

  const version = framework.version || framework.nuxtVersion;
  const isVulnerable = checkDevInjectionVulnerable(version);

  // Always flag exposed dev server
  results.push({
    type: 'Configuration',
    name: 'Nuxt Development Server Exposed',
    severity: SEVERITY.HIGH,
    description: 'Nuxt development server is publicly accessible. This exposes debugging tools and may allow code execution.',
    url,
    framework: framework.framework,
    version,
    isDev: true,
    remediation: 'Never expose development servers to the public internet'
  });

  if (isVulnerable === true) {
    results.push({
      type: 'RCE',
      name: 'Nuxt Dev Server Injection (CVE-2023-3224)',
      severity: SEVERITY.CRITICAL,
      cvss: 9.8,
      cve: 'CVE-2023-3224',
      description: `Nuxt ${version} dev server is vulnerable to code injection via error overlay.`,
      url,
      framework: framework.framework,
      version,
      isDev: true,
      exploitable: true,
      requiresProbe: true,
      testVector: 'Inject Vue template code in URL parameters',
      remediation: 'Upgrade to Nuxt 3.4.4 or later'
    });
  }

  // Active probing
  if (settings?.scanMode === 'active' && isVulnerable) {
    const probeResult = await probeDevInjection(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to dev injection
 */
function checkDevInjectionVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 3.4.0 to 3.4.3
  if (parts[0] === 3 && parts[1] === 4 && parts[2] >= 0 && parts[2] <= 3) {
    return true;
  }

  return false;
}

/**
 * Probe dev server injection
 */
async function probeDevInjection(url, context) {
  const probeId = generateSafeId();

  // Safe test payload that doesn't execute anything harmful
  const testPayloads = [
    `{{1+1}}`,  // Template expression
    `${probeId}{{constructor}}`,  // Constructor access attempt
  ];

  for (const payload of testPayloads) {
    try {
      const testUrl = new URL(url);
      testUrl.searchParams.set('__nuxt_error', payload);

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });

      const body = await response.text();

      // Check for template evaluation
      if (body.includes('2') && payload === '{{1+1}}') {
        return {
          type: 'RCE',
          name: 'Dev Server Injection - Template Evaluated',
          severity: SEVERITY.CRITICAL,
          cvss: 9.8,
          cve: 'CVE-2023-3224',
          description: 'Vue template expression was evaluated. RCE is possible.',
          url: testUrl.toString(),
          probeId,
          evidence: 'Template {{1+1}} evaluated to 2',
          exploitable: true
        };
      }

      // Check for error overlay with our payload
      if (body.includes('nuxt-error') || body.includes('__nuxt_error')) {
        return {
          type: 'RCE',
          name: 'Dev Server Injection - Error Overlay Active',
          severity: SEVERITY.HIGH,
          description: 'Error overlay is active and accepts parameters.',
          url: testUrl.toString(),
          probeId,
          note: 'Further testing with specific CVE payload recommended'
        };
      }
    } catch (e) {
      // Request failed
    }
  }

  return null;
}

/**
 * Prototype Pollution Scanner (CVE-2025-8083)
 * Detects Vuetify mergeDeep prototype pollution
 */
export async function prototypePollutionScanner(context) {
  const { framework, url, capturedRequests, settings } = context;
  const results = [];

  // Check for Vuetify
  const hasVuetify = framework?.hasVuetify ||
    (context.document && context.document.querySelector('v-app, .v-application'));

  if (!hasVuetify) {
    return results;
  }

  const version = framework?.vuetifyVersion;
  const isVulnerable = checkPrototypePollutionVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'Prototype Pollution',
      name: 'Vuetify Prototype Pollution (CVE-2025-8083)',
      severity: SEVERITY.HIGH,
      cvss: 7.5,
      cve: 'CVE-2025-8083',
      description: `Vuetify ${version} mergeDeep function is vulnerable to prototype pollution.`,
      url,
      framework: 'Vuetify',
      version,
      requiresProbe: true,
      testVector: 'JSON payload with __proto__ key',
      remediation: 'Upgrade to Vuetify 3.7.1 or later',
      note: 'In SSR context, this may lead to DoS or RCE'
    });
  } else if (hasVuetify) {
    results.push({
      type: 'Configuration',
      name: 'Vuetify Detected',
      severity: SEVERITY.INFO,
      description: 'Vuetify component library detected.',
      url,
      framework: 'Vuetify',
      version: version || 'unknown',
      note: 'Verify version for CVE-2025-8083'
    });
  }

  // Active probing
  if (settings?.scanMode === 'active' && isVulnerable !== false) {
    const probeResult = await probePrototypePollution(url, capturedRequests, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if Vuetify version is vulnerable to prototype pollution
 */
function checkPrototypePollutionVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 3.0.0 to 3.7.0
  if (parts[0] === 3 && parts[1] >= 0 && parts[1] <= 7) {
    if (parts[1] < 7 || (parts[1] === 7 && parts[2] === 0)) {
      return true;
    }
  }

  return false;
}

/**
 * Probe prototype pollution vulnerability
 */
async function probePrototypePollution(url, capturedRequests, context) {
  // Find JSON API endpoints
  const jsonEndpoints = capturedRequests.filter(r =>
    r.headers?.['content-type']?.includes('application/json') &&
    (r.method === 'POST' || r.method === 'PUT' || r.method === 'PATCH')
  );

  if (jsonEndpoints.length === 0) {
    return null;
  }

  const probeId = generateSafeId();

  // Safe prototype pollution probe
  const pollutionPayloads = [
    { "__proto__": { "polluted": probeId } },
    { "constructor": { "prototype": { "polluted": probeId } } }
  ];

  for (const endpoint of jsonEndpoints.slice(0, 3)) {
    for (const payload of pollutionPayloads) {
      try {
        const response = await fetch(endpoint.url, {
          method: endpoint.method,
          headers: {
            'Content-Type': 'application/json',
            'X-BlueDragon-Probe': probeId
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000)
        });

        // Check for errors that indicate pollution attempt was processed
        if (response.status === 500) {
          return {
            type: 'Prototype Pollution',
            name: 'Prototype Pollution - Server Error',
            severity: SEVERITY.MEDIUM,
            description: 'Server error when sending __proto__ payload. May indicate vulnerability.',
            url: endpoint.url,
            probeId,
            responseStatus: response.status,
            note: 'Server crashed or threw error on prototype pollution attempt'
          };
        }

        // If request succeeded, check response for pollution evidence
        if (response.ok) {
          const body = await response.text();
          if (body.includes(probeId)) {
            return {
              type: 'Prototype Pollution',
              name: 'Prototype Pollution - Reflected',
              severity: SEVERITY.HIGH,
              description: 'Prototype pollution payload reflected in response.',
              url: endpoint.url,
              probeId,
              evidence: 'Probe ID found in response'
            };
          }
        }
      } catch (e) {
        // Request failed
      }
    }
  }

  return null;
}

/**
 * Nuxt Devtools RCE Scanner (CVE-2024-23657)
 * Detects path traversal and RCE in Nuxt Devtools
 */
export async function devtoolsRCEScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to Nuxt
  if (framework?.framework !== 'Nuxt') {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkDevtoolsRCEVulnerable(version);

  // Check for Devtools endpoints
  const devtoolsPaths = [
    '/_nuxt-devtools/',
    '/__nuxt_devtools__/',
    '/_devtools/',
    '/@nuxt/devtools'
  ];

  let devtoolsFound = false;

  for (const path of devtoolsPaths) {
    try {
      const testUrl = new URL(path, url);
      const response = await fetch(testUrl.toString(), {
        method: 'HEAD',
        signal: AbortSignal.timeout(3000)
      });

      if (response.status !== 404) {
        devtoolsFound = true;

        results.push({
          type: 'Configuration',
          name: 'Nuxt Devtools Exposed',
          severity: SEVERITY.HIGH,
          description: 'Nuxt Devtools endpoint is publicly accessible.',
          url: testUrl.toString(),
          framework: framework.framework,
          version,
          path,
          remediation: 'Disable devtools in production or restrict access'
        });

        if (isVulnerable === true) {
          results.push({
            type: 'RCE',
            name: 'Nuxt Devtools RCE (CVE-2024-23657)',
            severity: SEVERITY.CRITICAL,
            cvss: 9.8,
            cve: 'CVE-2024-23657',
            description: `Nuxt Devtools vulnerable to path traversal and RCE`,
            url: testUrl.toString(),
            framework: framework.framework,
            version,
            exploitable: true,
            requiresProbe: true,
            testVector: 'Path traversal via devtools file read endpoint',
            remediation: 'Upgrade to @nuxt/devtools 1.3.9+ or disable devtools'
          });
        }

        break;
      }
    } catch (e) {
      // Request failed
    }
  }

  // Active probing for path traversal
  if (settings?.scanMode === 'active' && devtoolsFound) {
    const probeResult = await probeDevtoolsRCE(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to Devtools RCE
 */
function checkDevtoolsRCEVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Devtools versions 0.1.0 to 1.3.8 are vulnerable
  // Since we don't easily get devtools version, check Nuxt version
  // Nuxt 3.x bundles devtools by default from 3.8+
  if (parts[0] === 3 && parts[1] >= 8) {
    return 'unknown'; // May have vulnerable devtools
  }

  return false;
}

/**
 * Probe Devtools path traversal
 */
async function probeDevtoolsRCE(url, context) {
  const probeId = generateSafeId();

  // Path traversal payloads
  const traversalPayloads = [
    '/../../../etc/passwd',
    '/../../../package.json',
    '/..%2f..%2f..%2fetc%2fpasswd',
    '/....//....//....//etc/passwd'
  ];

  for (const payload of traversalPayloads) {
    try {
      const testUrl = new URL(`/_nuxt-devtools/api/read-file${payload}`, url);

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        headers: {
          'X-BlueDragon-Probe': probeId
        },
        signal: AbortSignal.timeout(5000)
      });

      const body = await response.text();

      // Check for path traversal success
      if (body.includes('root:') || body.includes('"name":') || body.includes('dependencies')) {
        return {
          type: 'RCE',
          name: 'Devtools Path Traversal - Confirmed',
          severity: SEVERITY.CRITICAL,
          cve: 'CVE-2024-23657',
          description: 'Path traversal via Devtools allows arbitrary file read.',
          url: testUrl.toString(),
          probeId,
          payload,
          exploitable: true,
          note: 'Arbitrary file read confirmed, RCE may be possible'
        };
      }
    } catch (e) {
      // Request failed
    }
  }

  return null;
}

/**
 * Nuxt TestComponentWrapper RCE Scanner (CVE-2024-34344)
 * Detects exposed TestComponentWrapper in production
 */
export async function testComponentRCEScanner(context) {
  const { framework, url, settings } = context;
  const results = [];

  // Only applicable to Nuxt
  if (framework?.framework !== 'Nuxt') {
    return results;
  }

  const version = framework.version;
  const isVulnerable = checkTestComponentVulnerable(version);

  if (isVulnerable === true) {
    results.push({
      type: 'RCE',
      name: 'Nuxt TestComponentWrapper RCE (CVE-2024-34344)',
      severity: SEVERITY.CRITICAL,
      cvss: 9.8,
      cve: 'CVE-2024-34344',
      description: `Nuxt ${version} may expose TestComponentWrapper in production allowing arbitrary component rendering`,
      url,
      framework: framework.framework,
      version,
      requiresProbe: true,
      exploitConditions: 'Test utilities bundled in production',
      remediation: 'Upgrade to Nuxt 3.11.3+ or ensure test components are not bundled'
    });
  }

  // Check for TestComponentWrapper exposure
  const testWrapperPaths = [
    '/_nuxt/@nuxt/test-utils',
    '/_nuxt/test-utils',
    '/__nuxt_test_wrapper__'
  ];

  for (const path of testWrapperPaths) {
    try {
      const testUrl = new URL(path, url);
      const response = await fetch(testUrl.toString(), {
        method: 'HEAD',
        signal: AbortSignal.timeout(3000)
      });

      if (response.status !== 404) {
        results.push({
          type: 'RCE',
          name: 'Test Component Wrapper Exposed',
          severity: SEVERITY.HIGH,
          description: 'Nuxt test utilities are accessible in production.',
          url: testUrl.toString(),
          framework: framework.framework,
          path,
          note: 'May allow arbitrary component rendering'
        });
        break;
      }
    } catch (e) {
      // Request failed
    }
  }

  // Active probing
  if (settings?.scanMode === 'active') {
    const probeResult = await probeTestComponent(url, context);
    if (probeResult) {
      results.push(probeResult);
    }
  }

  return results;
}

/**
 * Check if version is vulnerable to TestComponent RCE
 */
function checkTestComponentVulnerable(version) {
  if (!version) return 'unknown';

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Vulnerable: 3.4.0 to 3.11.2
  if (parts[0] === 3) {
    if (parts[1] >= 4 && parts[1] <= 11) {
      if (parts[1] < 11 || (parts[1] === 11 && parts[2] <= 2)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Probe TestComponentWrapper
 */
async function probeTestComponent(url, context) {
  const probeId = generateSafeId();

  // Try to render a test component
  const testPayloads = [
    { component: 'NuxtPage', props: {} },
    { component: 'NuxtLayout', props: { name: 'default' } },
    { render: `<div>${probeId}</div>` }
  ];

  const wrapperEndpoints = [
    '/__nuxt_test_wrapper__/render',
    '/_nuxt/test-utils/render'
  ];

  for (const endpoint of wrapperEndpoints) {
    for (const payload of testPayloads) {
      try {
        const testUrl = new URL(endpoint, url);

        const response = await fetch(testUrl.toString(), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-BlueDragon-Probe': probeId
          },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000)
        });

        if (response.ok || response.status === 200) {
          const body = await response.text();

          if (body.includes(probeId) || body.includes('<div>') || body.includes('NuxtPage')) {
            return {
              type: 'RCE',
              name: 'Test Component Rendering - Confirmed',
              severity: SEVERITY.CRITICAL,
              cve: 'CVE-2024-34344',
              description: 'TestComponentWrapper accepted render request.',
              url: testUrl.toString(),
              probeId,
              exploitable: true,
              note: 'Arbitrary component rendering possible'
            };
          }
        }
      } catch (e) {
        // Request failed
      }
    }
  }

  return null;
}

export default {
  devInjectionScanner,
  prototypePollutionScanner,
  devtoolsRCEScanner,
  testComponentRCEScanner
};
