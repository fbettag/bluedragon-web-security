/**
 * BlueDragon Web Security - Framework Detection Module
 * Main orchestrator for detecting frontend frameworks and their versions
 */

import { FRAMEWORKS } from '../shared/constants.js';
import {
  FRAMEWORK_SIGNATURES,
  RSC_SIGNATURES,
  getOrderedSignatures
} from '../shared/framework-signatures.js';
import { detectReact, detectNextJs } from './react-detector.js';
import { detectAngular } from './angular-detector.js';
import { detectSvelteKit } from './svelte-detector.js';
import { detectNuxt, detectVue } from './vue-detector.js';
import { detectWaku, detectReactRouter, detectRedwood } from './rsc-detector.js';
import { extractVersionFromAssets } from './version-fingerprint.js';

/**
 * Main framework detection result
 * @typedef {Object} DetectionResult
 * @property {string} framework - Framework identifier
 * @property {string|null} version - Detected version (if available)
 * @property {boolean} isSSR - Whether SSR is detected
 * @property {boolean} hasRSC - Whether React Server Components are detected
 * @property {number} confidence - Detection confidence (0-100)
 * @property {string[]} indicators - List of detection indicators found
 * @property {Object[]} vulnerabilities - Potential vulnerabilities based on version
 */

/**
 * Detect all frameworks present on the current page
 * @param {Document} doc - Document object to analyze
 * @param {Object} options - Detection options
 * @returns {Promise<DetectionResult[]>} - Array of detected frameworks
 */
export async function detectFrameworks(doc = document, options = {}) {
  const results = [];
  const html = doc.documentElement.outerHTML;
  const scripts = Array.from(doc.querySelectorAll('script'));
  const links = Array.from(doc.querySelectorAll('link'));

  // Get all script content for deep analysis
  const scriptContents = await getScriptContents(scripts);

  // Run detectors in priority order
  const detectors = [
    { id: FRAMEWORKS.NEXTJS, fn: detectNextJs },
    { id: FRAMEWORKS.ANGULAR, fn: detectAngular },
    { id: FRAMEWORKS.SVELTEKIT, fn: detectSvelteKit },
    { id: FRAMEWORKS.NUXT, fn: detectNuxt },
    { id: FRAMEWORKS.REACT, fn: detectReact },
    { id: FRAMEWORKS.VUE, fn: detectVue },
    { id: FRAMEWORKS.WAKU, fn: detectWaku },
    { id: FRAMEWORKS.REACT_ROUTER, fn: detectReactRouter },
    { id: FRAMEWORKS.REDWOOD, fn: detectRedwood }
  ];

  for (const detector of detectors) {
    try {
      const result = await detector.fn(doc, html, scriptContents, options);
      if (result && result.confidence > 30) {
        results.push(result);
      }
    } catch (error) {
      console.warn(`[BlueDragon] Error in ${detector.id} detector:`, error);
    }
  }

  // Sort by confidence
  results.sort((a, b) => b.confidence - a.confidence);

  return results;
}

/**
 * Quick detection for popup display (faster, less thorough)
 * @param {Document} doc - Document to analyze
 * @returns {DetectionResult|null} - Primary detected framework
 */
export function quickDetect(doc = document) {
  const html = doc.documentElement.innerHTML;

  // Quick checks in priority order
  // Next.js
  if (html.includes('__NEXT_DATA__') || html.includes('/_next/')) {
    return {
      framework: FRAMEWORKS.NEXTJS,
      version: extractQuickVersion(html, 'next'),
      isSSR: true,
      hasRSC: html.includes('_rsc') || html.includes('text/x-component'),
      confidence: 90,
      indicators: ['__NEXT_DATA__']
    };
  }

  // Angular
  const ngVersion = doc.querySelector('[ng-version]');
  if (ngVersion || html.includes('@angular/core')) {
    return {
      framework: FRAMEWORKS.ANGULAR,
      version: ngVersion?.getAttribute('ng-version') || null,
      isSSR: html.includes('ng-server-context') || html.includes('serverApp'),
      hasRSC: false,
      confidence: 90,
      indicators: ngVersion ? ['ng-version attribute'] : ['@angular/core']
    };
  }

  // SvelteKit
  if (html.includes('__sveltekit') || html.includes('/_app/immutable/')) {
    return {
      framework: FRAMEWORKS.SVELTEKIT,
      version: null,
      isSSR: html.includes('data-sveltekit-hydrate'),
      hasRSC: false,
      confidence: 85,
      indicators: ['__sveltekit']
    };
  }

  // Nuxt
  if (html.includes('__NUXT__') || html.includes('/_nuxt/')) {
    return {
      framework: FRAMEWORKS.NUXT,
      version: null,
      isSSR: html.includes('serverRendered') || html.includes('data-server-rendered'),
      hasRSC: false,
      confidence: 85,
      indicators: ['__NUXT__']
    };
  }

  // React (generic)
  if (html.includes('data-reactroot') || html.includes('__REACT_DEVTOOLS_GLOBAL_HOOK__')) {
    return {
      framework: FRAMEWORKS.REACT,
      version: null,
      isSSR: false,
      hasRSC: false,
      confidence: 70,
      indicators: ['React markers']
    };
  }

  // Vue (generic)
  if (html.includes('data-v-') || html.includes('__VUE__')) {
    return {
      framework: FRAMEWORKS.VUE,
      version: null,
      isSSR: false,
      hasRSC: false,
      confidence: 70,
      indicators: ['Vue markers']
    };
  }

  // Waku
  if (html.includes('__WAKU_') || html.includes('waku')) {
    return {
      framework: FRAMEWORKS.WAKU,
      version: null,
      isSSR: true,
      hasRSC: true,
      confidence: 75,
      indicators: ['Waku markers']
    };
  }

  // React Router v7+
  if (html.includes('__reactRouterVersion') || html.includes('@react-router')) {
    return {
      framework: FRAMEWORKS.REACT_ROUTER,
      version: null,
      isSSR: true,
      hasRSC: html.includes('_rsc') || html.includes('text/x-component'),
      confidence: 75,
      indicators: ['React Router markers']
    };
  }

  // RedwoodJS
  if (html.includes('__REDWOOD__') || html.includes('@redwoodjs')) {
    return {
      framework: FRAMEWORKS.REDWOOD,
      version: null,
      isSSR: true,
      hasRSC: true,
      confidence: 80,
      indicators: ['RedwoodJS markers']
    };
  }

  return null;
}

/**
 * Detect React Server Components / Flight protocol usage
 * @param {Document} doc - Document to analyze
 * @returns {Object} - RSC detection result
 */
export function detectRSC(doc = document) {
  const result = {
    detected: false,
    indicators: [],
    endpoints: [],
    flightData: null
  };

  // Check for RSC markers in HTML
  const html = doc.documentElement.innerHTML;

  // Check __NEXT_DATA__ for RSC flag
  const nextDataScript = doc.querySelector('#__NEXT_DATA__');
  if (nextDataScript) {
    try {
      const data = JSON.parse(nextDataScript.textContent);
      if (data.rsc || data.isRsc) {
        result.detected = true;
        result.indicators.push('__NEXT_DATA__ RSC flag');
      }
    } catch (e) {
      // Ignore parse errors
    }
  }

  // Check for _rsc query parameter usage
  if (html.includes('_rsc=')) {
    result.detected = true;
    result.indicators.push('_rsc query parameter');
  }

  // Check for Flight protocol content type references
  if (html.includes('text/x-component')) {
    result.detected = true;
    result.indicators.push('text/x-component content type');
  }

  // Check for Flight chunk patterns in inline scripts
  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent || '';
    if (RSC_SIGNATURES.response.patterns.some(p => p.test(content))) {
      result.detected = true;
      result.indicators.push('Flight protocol chunk patterns');
      break;
    }
  }

  return result;
}

/**
 * Get script contents for analysis
 * @param {HTMLScriptElement[]} scripts - Script elements
 * @returns {Promise<Map<string, string>>} - Map of URL/ID to content
 */
async function getScriptContents(scripts) {
  const contents = new Map();

  for (const script of scripts) {
    // Inline scripts
    if (!script.src && script.textContent) {
      contents.set(`inline-${scripts.indexOf(script)}`, script.textContent);
    }

    // External scripts (fetch if same-origin)
    if (script.src) {
      try {
        const url = new URL(script.src, window.location.origin);
        if (url.origin === window.location.origin) {
          // We'll do this via message passing to background in actual implementation
          // For now, just store the URL
          contents.set(script.src, `[external: ${script.src}]`);
        }
      } catch (e) {
        // Invalid URL
      }
    }
  }

  return contents;
}

/**
 * Quick version extraction from HTML content
 * @param {string} html - HTML content
 * @param {string} framework - Framework name
 * @returns {string|null} - Extracted version
 */
function extractQuickVersion(html, framework) {
  const patterns = {
    next: [
      /"next":\s*"([^"]+)"/,
      /Next\.js\s+([\d.]+)/
    ],
    react: [
      /"react":\s*"([^"]+)"/,
      /React\s+([\d.]+)/
    ],
    angular: [
      /@angular\/core@([\d.]+)/
    ],
    svelte: [
      /svelte@([\d.]+)/
    ],
    nuxt: [
      /"nuxt":\s*"([^"]+)"/
    ],
    vue: [
      /"vue":\s*"([^"]+)"/,
      /Vue\.version\s*=\s*["']([\d.]+)/
    ]
  };

  const frameworkPatterns = patterns[framework] || [];
  for (const pattern of frameworkPatterns) {
    const match = html.match(pattern);
    if (match) {
      return match[1].replace(/[~^]/, '');
    }
  }

  return null;
}

/**
 * Check if detected version is vulnerable
 * @param {string} framework - Framework identifier
 * @param {string} version - Detected version
 * @returns {Object[]} - List of potential vulnerabilities
 */
export function checkVulnerableVersion(framework, version) {
  if (!version) return [];

  const { VULNERABLE_VERSIONS, CVE_DATABASE } = require('../shared/constants.js');
  const vulnerabilities = [];

  // Check each CVE
  for (const [cveId, cve] of Object.entries(CVE_DATABASE)) {
    if (!cve.frameworks.includes(framework)) continue;

    // Get affected versions for this CVE
    const affectedKey = Object.keys(VULNERABLE_VERSIONS).find(key =>
      key.toLowerCase().includes(framework.toLowerCase())
    );

    if (affectedKey) {
      const affected = VULNERABLE_VERSIONS[affectedKey];
      if (isVersionAffected(version, affected)) {
        vulnerabilities.push({
          cve: cveId,
          ...cve
        });
      }
    }
  }

  return vulnerabilities;
}

/**
 * Check if a version is in the affected range
 * @param {string} version - Version to check
 * @param {string[]} affected - Array of affected versions or ranges
 * @returns {boolean}
 */
function isVersionAffected(version, affected) {
  // Normalize version
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];

  for (const affectedVersion of affected) {
    // Handle ranges like "16.0.0-21.0.0-next.3"
    if (affectedVersion.includes('-') && affectedVersion.split('-').length >= 2) {
      const [min, max] = affectedVersion.split('-');
      if (compareVersions(normalizedVersion, min) >= 0 &&
          compareVersions(normalizedVersion, max) <= 0) {
        return true;
      }
    }

    // Exact match
    if (normalizedVersion === affectedVersion) {
      return true;
    }
  }

  return false;
}

/**
 * Compare two semantic versions
 * @param {string} v1 - First version
 * @param {string} v2 - Second version
 * @returns {number} - -1, 0, or 1
 */
function compareVersions(v1, v2) {
  const parts1 = v1.split('.').map(p => parseInt(p, 10) || 0);
  const parts2 = v2.split('.').map(p => parseInt(p, 10) || 0);

  const maxLength = Math.max(parts1.length, parts2.length);
  for (let i = 0; i < maxLength; i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }

  return 0;
}

export default {
  detectFrameworks,
  quickDetect,
  detectRSC,
  checkVulnerableVersion
};
