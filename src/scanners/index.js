/**
 * BlueDragon Web Security - Scanner Pipeline
 * Orchestrates vulnerability scanning across all modules
 */

import { SEVERITY, FRAMEWORKS } from '../shared/constants.js';
import { isBlockedEndpoint, requiresConfirmation, RateLimiter } from '../shared/safety-filters.js';

// Import framework-specific scanners
import * as reactScanners from './react/index.js';
import * as angularScanners from './angular/index.js';
import * as svelteScanners from './svelte/index.js';
import * as vueScanners from './vue/index.js';
import * as genericScanners from './generic/index.js';

/**
 * Scanner pipeline configuration
 */
const SCANNER_MODULES = {
  [FRAMEWORKS.NEXTJS]: [
    { name: 'react2shell', scanner: reactScanners.react2shellScanner, priority: 1 },
    { name: 'middleware-bypass', scanner: reactScanners.middlewareBypassScanner, priority: 2 },
    { name: 'server-action-ssrf', scanner: reactScanners.serverActionSSRFScanner, priority: 3 },
    { name: 'source-exposure', scanner: reactScanners.sourceCodeExposureScanner, priority: 4 },
    { name: 'react-dos', scanner: reactScanners.reactDoSScanner, priority: 5 },
    { name: 'image-dos', scanner: reactScanners.imageDoSScanner, priority: 6 }
  ],
  [FRAMEWORKS.REACT]: [
    { name: 'react2shell', scanner: reactScanners.react2shellScanner, priority: 1 },
    { name: 'source-exposure', scanner: reactScanners.sourceCodeExposureScanner, priority: 2 },
    { name: 'react-dos', scanner: reactScanners.reactDoSScanner, priority: 3 }
  ],
  [FRAMEWORKS.WAKU]: [
    { name: 'react2shell', scanner: reactScanners.react2shellScanner, priority: 1 },
    { name: 'source-exposure', scanner: reactScanners.sourceCodeExposureScanner, priority: 2 },
    { name: 'react-dos', scanner: reactScanners.reactDoSScanner, priority: 3 }
  ],
  [FRAMEWORKS.REACT_ROUTER]: [
    { name: 'react2shell', scanner: reactScanners.react2shellScanner, priority: 1 },
    { name: 'source-exposure', scanner: reactScanners.sourceCodeExposureScanner, priority: 2 },
    { name: 'react-dos', scanner: reactScanners.reactDoSScanner, priority: 3 }
  ],
  [FRAMEWORKS.REDWOOD]: [
    { name: 'react2shell', scanner: reactScanners.react2shellScanner, priority: 1 },
    { name: 'source-exposure', scanner: reactScanners.sourceCodeExposureScanner, priority: 2 },
    { name: 'react-dos', scanner: reactScanners.reactDoSScanner, priority: 3 }
  ],
  [FRAMEWORKS.ANGULAR]: [
    { name: 'race-condition', scanner: angularScanners.raceConditionScanner, priority: 1 },
    { name: 'url-ssrf', scanner: angularScanners.urlSSRFScanner, priority: 2 },
    { name: 'xsrf-leak', scanner: angularScanners.xsrfLeakScanner, priority: 3 },
    { name: 'angular-xss', scanner: angularScanners.angularXSSScanner, priority: 4 }
  ],
  [FRAMEWORKS.SVELTEKIT]: [
    { name: 'csrf-bypass', scanner: svelteScanners.csrfBypassScanner, priority: 1 },
    { name: 'template-injection', scanner: svelteScanners.templateInjectionScanner, priority: 2 },
    { name: 'searchparams-xss', scanner: svelteScanners.searchParamsXSSScanner, priority: 3 }
  ],
  [FRAMEWORKS.NUXT]: [
    { name: 'dev-injection', scanner: vueScanners.devInjectionScanner, priority: 1 },
    { name: 'devtools-rce', scanner: vueScanners.devtoolsRCEScanner, priority: 2 },
    { name: 'testcomponent-rce', scanner: vueScanners.testComponentRCEScanner, priority: 3 },
    { name: 'prototype-pollution', scanner: vueScanners.prototypePollutionScanner, priority: 4 }
  ],
  [FRAMEWORKS.VUE]: [
    { name: 'prototype-pollution', scanner: vueScanners.prototypePollutionScanner, priority: 1 }
  ]
};

/**
 * Generic scanners that run regardless of framework
 */
const GENERIC_SCANNERS = [
  { name: 'security-headers', scanner: genericScanners.securityHeadersScanner, priority: 10 },
  { name: 'csrf', scanner: genericScanners.csrfScanner, priority: 11 },
  { name: 'ssrf', scanner: genericScanners.ssrfScanner, priority: 12 },
  { name: 'header-injection', scanner: genericScanners.headerInjectionScanner, priority: 13 }
];

/**
 * Run the scanner pipeline
 * @param {Object} context - Scan context
 * @returns {Promise<Object[]>} - Scan results
 */
export async function runScannerPipeline(context) {
  const {
    framework,
    url,
    document: doc,
    settings = {},
    capturedRequests = [],
    rateLimiter = new RateLimiter(5)
  } = context;

  const results = [];
  const scanners = [];

  // Add framework-specific scanners
  if (framework?.framework && SCANNER_MODULES[framework.framework]) {
    scanners.push(...SCANNER_MODULES[framework.framework]);
  }

  // Add generic scanners
  scanners.push(...GENERIC_SCANNERS);

  // Sort by priority
  scanners.sort((a, b) => a.priority - b.priority);

  // Run each scanner
  for (const { name, scanner } of scanners) {
    try {
      // Check if URL is blocked
      if (isBlockedEndpoint(url)) {
        console.log(`[BlueDragon] Skipping ${name} - blocked endpoint`);
        continue;
      }

      // Rate limit
      await rateLimiter.throttle();

      console.log(`[BlueDragon] Running scanner: ${name}`);

      const scannerResults = await scanner({
        framework,
        url,
        document: doc,
        settings,
        capturedRequests,
        rateLimiter
      });

      if (scannerResults && scannerResults.length > 0) {
        // Add scanner name to results
        for (const result of scannerResults) {
          result.scanner = name;
          result.id = result.id || generateId();
        }

        results.push(...scannerResults);
      }
    } catch (error) {
      console.error(`[BlueDragon] Scanner ${name} error:`, error);
    }
  }

  // Sort results by severity
  results.sort((a, b) => {
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
  });

  return results;
}

/**
 * Run a single scanner by name
 * @param {string} scannerName - Name of scanner to run
 * @param {Object} context - Scan context
 * @returns {Promise<Object[]>} - Scan results
 */
export async function runSingleScanner(scannerName, context) {
  // Find the scanner
  let scanner = null;

  for (const framework of Object.values(SCANNER_MODULES)) {
    const found = framework.find(s => s.name === scannerName);
    if (found) {
      scanner = found.scanner;
      break;
    }
  }

  if (!scanner) {
    const genericFound = GENERIC_SCANNERS.find(s => s.name === scannerName);
    if (genericFound) {
      scanner = genericFound.scanner;
    }
  }

  if (!scanner) {
    throw new Error(`Scanner not found: ${scannerName}`);
  }

  return await scanner(context);
}

/**
 * Get list of available scanners
 * @param {string} framework - Optional framework filter
 * @returns {Object[]} - List of scanner info
 */
export function getAvailableScanners(framework = null) {
  const scanners = [];

  if (framework && SCANNER_MODULES[framework]) {
    for (const s of SCANNER_MODULES[framework]) {
      scanners.push({
        name: s.name,
        framework,
        priority: s.priority
      });
    }
  } else {
    // All scanners
    for (const [fw, modules] of Object.entries(SCANNER_MODULES)) {
      for (const s of modules) {
        scanners.push({
          name: s.name,
          framework: fw,
          priority: s.priority
        });
      }
    }
  }

  // Add generic
  for (const s of GENERIC_SCANNERS) {
    scanners.push({
      name: s.name,
      framework: 'generic',
      priority: s.priority
    });
  }

  return scanners;
}

/**
 * Generate unique ID
 */
function generateId() {
  return 'wd-' + Math.random().toString(36).substr(2, 9);
}

export default {
  runScannerPipeline,
  runSingleScanner,
  getAvailableScanners
};
