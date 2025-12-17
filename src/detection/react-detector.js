/**
 * BlueDragon Web Security - React/Next.js Detector
 * Detects React and Next.js frameworks with version fingerprinting
 */

import { FRAMEWORKS } from '../shared/constants.js';
import { FRAMEWORK_SIGNATURES, RSC_SIGNATURES } from '../shared/framework-signatures.js';

/**
 * Detect Next.js framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectNextJs(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.NEXTJS,
    version: null,
    isSSR: false,
    hasRSC: false,
    hasAppRouter: false,
    hasPagesRouter: false,
    confidence: 0,
    indicators: [],
    buildId: null,
    serverActions: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.NEXTJS];

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'script' && sig.pattern.test(html)) {
      result.indicators.push(`HTML: ${sig.pattern.source}`);
      result.confidence += 25;
    }
    if (sig.type === 'attribute') {
      if (doc.querySelector(sig.selector)) {
        result.indicators.push(`Attribute: ${sig.selector}`);
        result.confidence += 20;
      }
    }
  }

  // Check URL patterns in page resources
  const allUrls = [
    ...Array.from(doc.querySelectorAll('script[src]')).map(s => s.src),
    ...Array.from(doc.querySelectorAll('link[href]')).map(l => l.href),
    ...Array.from(doc.querySelectorAll('img[src]')).map(i => i.src)
  ];

  for (const url of allUrls) {
    for (const pattern of signatures.signatures.urls) {
      if (pattern.test(url)) {
        result.indicators.push(`URL: ${pattern.source}`);
        result.confidence += 15;
        break;
      }
    }
  }

  // Extract __NEXT_DATA__ for detailed info
  const nextDataScript = doc.querySelector('#__NEXT_DATA__');
  if (nextDataScript) {
    result.indicators.push('__NEXT_DATA__ script tag');
    result.confidence += 30;

    try {
      const nextData = JSON.parse(nextDataScript.textContent);

      // Extract build ID
      if (nextData.buildId) {
        result.buildId = nextData.buildId;
        result.indicators.push(`Build ID: ${nextData.buildId}`);
      }

      // Check for App Router (RSC)
      if (nextData.rsc || nextData.isRsc) {
        result.hasRSC = true;
        result.hasAppRouter = true;
        result.isSSR = true;
        result.indicators.push('App Router (RSC) enabled');
        result.confidence += 10;
      }

      // Check for Pages Router
      if (nextData.page && !result.hasAppRouter) {
        result.hasPagesRouter = true;
        result.indicators.push(`Pages Router: ${nextData.page}`);
      }

      // Check for SSR
      if (nextData.props?.pageProps || nextData.props) {
        result.isSSR = true;
        result.indicators.push('Server-side props detected');
      }

      // Try to extract version from runtime config
      if (nextData.runtimeConfig?.version) {
        result.version = nextData.runtimeConfig.version;
      }
    } catch (e) {
      // JSON parse error, but still detected Next.js
    }
  }

  // Check for _next static paths
  const nextStatic = doc.querySelector('script[src*="/_next/static/"]');
  if (nextStatic) {
    result.indicators.push('_next/static resources');
    result.confidence += 20;

    // Try to extract build ID from path
    const buildMatch = nextStatic.src.match(/_next\/static\/([^/]+)\//);
    if (buildMatch && !result.buildId) {
      result.buildId = buildMatch[1];
    }
  }

  // Check for RSC indicators
  const rscResult = detectRSCIndicators(doc, html);
  if (rscResult.detected) {
    result.hasRSC = true;
    result.indicators.push(...rscResult.indicators);
    result.confidence += 15;
  }

  // Detect Server Actions
  result.serverActions = detectServerActions(doc, html);
  if (result.serverActions.length > 0) {
    result.indicators.push(`${result.serverActions.length} Server Actions detected`);
    result.confidence += 10;
  }

  // Try to extract version from chunks
  if (!result.version) {
    result.version = await extractNextVersion(doc, allUrls);
  }

  // Cap confidence at 100
  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Detect generic React (when not Next.js)
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectReact(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.REACT,
    version: null,
    isSSR: false,
    hasRSC: false,
    confidence: 0,
    indicators: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.REACT];

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'attribute' && doc.querySelector(sig.selector)) {
      result.indicators.push(`Attribute: ${sig.selector}`);
      result.confidence += 25;
    }
  }

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script: ${pattern.source}`);
      result.confidence += 15;
    }
  }

  // Check for React DevTools hook
  if (typeof window !== 'undefined' && window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    result.indicators.push('React DevTools hook present');
    result.confidence += 20;
  }

  // Try to extract version
  for (const vp of signatures.versionPatterns) {
    if (vp.source === 'script') {
      const match = html.match(vp.pattern);
      if (match) {
        result.version = match[1].replace(/[~^]/, '');
        result.indicators.push(`Version: ${result.version}`);
        break;
      }
    }
  }

  // Check for data-reactroot (SSR indicator)
  if (doc.querySelector('[data-reactroot]')) {
    result.isSSR = true;
    result.indicators.push('Server-side rendered (data-reactroot)');
  }

  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Detect RSC (React Server Components) indicators
 * @param {Document} doc - Document to analyze
 * @param {string} html - HTML content
 * @returns {Object} - RSC detection result
 */
function detectRSCIndicators(doc, html) {
  const result = {
    detected: false,
    indicators: []
  };

  // Check for _rsc query parameter in links
  const rscLinks = doc.querySelectorAll('a[href*="_rsc="]');
  if (rscLinks.length > 0) {
    result.detected = true;
    result.indicators.push('RSC prefetch links detected');
  }

  // Check for text/x-component content type references
  if (html.includes('text/x-component')) {
    result.detected = true;
    result.indicators.push('Flight protocol content type');
  }

  // Check for Flight chunk patterns
  for (const pattern of RSC_SIGNATURES.response.patterns) {
    if (pattern.test(html)) {
      result.detected = true;
      result.indicators.push(`Flight pattern: ${pattern.source}`);
      break;
    }
  }

  // Check for Server Component markers in hydration data
  const hydrationScripts = doc.querySelectorAll('script[type="application/json"]');
  for (const script of hydrationScripts) {
    const content = script.textContent || '';
    if (content.includes('"rsc"') || content.includes('"flight"')) {
      result.detected = true;
      result.indicators.push('RSC hydration data');
      break;
    }
  }

  return result;
}

/**
 * Detect Server Actions in the page
 * @param {Document} doc - Document to analyze
 * @param {string} html - HTML content
 * @returns {Object[]} - Detected Server Actions
 */
function detectServerActions(doc, html) {
  const actions = [];

  // Check for form actions with $ACTION_ prefix
  const forms = doc.querySelectorAll('form');
  for (const form of forms) {
    const action = form.getAttribute('action');
    if (action && (action.includes('$ACTION') || action.startsWith('/'))) {
      // Check for hidden action ID input
      const actionIdInput = form.querySelector('input[name="$ACTION_ID"]');
      if (actionIdInput) {
        actions.push({
          type: 'form',
          action: action,
          actionId: actionIdInput.value,
          method: form.method || 'POST'
        });
      }
    }
  }

  // Check for action references in scripts
  const actionPattern = /\$ACTION_ID_([a-f0-9]+)/g;
  let match;
  while ((match = actionPattern.exec(html)) !== null) {
    actions.push({
      type: 'script',
      actionId: match[1]
    });
  }

  return actions;
}

/**
 * Try to extract Next.js version from assets
 * @param {Document} doc - Document
 * @param {string[]} urls - Resource URLs
 * @returns {Promise<string|null>} - Version or null
 */
async function extractNextVersion(doc, urls) {
  // Check for version in page source
  const pageSource = doc.documentElement.outerHTML;

  // Common version patterns
  const patterns = [
    /"next":\s*"([^"]+)"/,
    /next@([\d.]+)/,
    /Next\.js\s*([\d.]+)/
  ];

  for (const pattern of patterns) {
    const match = pageSource.match(pattern);
    if (match) {
      return match[1].replace(/[~^]/, '');
    }
  }

  // Could also fetch and parse framework chunks, but that's more intrusive
  return null;
}

/**
 * Check if Next.js version is vulnerable to React2Shell
 * @param {string} version - Next.js version
 * @returns {Object} - Vulnerability info
 */
export function checkReact2ShellVulnerable(version) {
  if (!version) {
    return { vulnerable: 'unknown', reason: 'Version not detected' };
  }

  // Vulnerable versions
  const vulnerableRanges = [
    { min: '15.0.0', max: '15.0.4' },
    { min: '16.0.0', max: '16.0.6' }
  ];

  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];

  for (const range of vulnerableRanges) {
    if (compareVersions(normalizedVersion, range.min) >= 0 &&
        compareVersions(normalizedVersion, range.max) <= 0) {
      return {
        vulnerable: true,
        reason: `Version ${version} is in vulnerable range ${range.min}-${range.max}`,
        cve: 'CVE-2025-55182',
        severity: 'CRITICAL'
      };
    }
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is not in known vulnerable ranges`
  };
}

/**
 * Compare semantic versions
 */
function compareVersions(v1, v2) {
  const parts1 = v1.split('.').map(p => parseInt(p, 10) || 0);
  const parts2 = v2.split('.').map(p => parseInt(p, 10) || 0);

  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const p1 = parts1[i] || 0;
    const p2 = parts2[i] || 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

export default {
  detectNextJs,
  detectReact,
  checkReact2ShellVulnerable
};
