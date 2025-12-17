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
