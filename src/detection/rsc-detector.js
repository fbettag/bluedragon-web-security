/**
 * BlueDragon Web Security - RSC Framework Detector
 * Detects Waku, React Router v7, and RedwoodJS frameworks
 * These all use React Server Components and are vulnerable to React2Shell
 */

import { FRAMEWORKS } from '../shared/constants.js';
import { FRAMEWORK_SIGNATURES, RSC_SIGNATURES } from '../shared/framework-signatures.js';

/**
 * Detect Waku framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectWaku(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.WAKU,
    version: null,
    isSSR: false,
    hasRSC: false,
    confidence: 0,
    indicators: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.WAKU];
  if (!signatures) return null;

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'script' && sig.pattern.test(html)) {
      result.indicators.push(`HTML: ${sig.pattern.source}`);
      result.confidence += 25;
    }
  }

  // Check URL patterns
  const allUrls = [
    ...Array.from(doc.querySelectorAll('script[src]')).map(s => s.src),
    ...Array.from(doc.querySelectorAll('link[href]')).map(l => l.href)
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

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script: ${pattern.source}`);
      result.confidence += 20;
    }
  }

  // Waku uses RSC
  const rscResult = detectRSCIndicatorsGeneric(doc, html);
  if (rscResult.detected) {
    result.hasRSC = true;
    result.isSSR = true;
    result.indicators.push(...rscResult.indicators);
    result.confidence += 15;
  }

  // Try to extract version
  result.version = extractWakuVersion(html);
  if (result.version) {
    result.indicators.push(`Version: ${result.version}`);
  }

  result.confidence = Math.min(100, result.confidence);
  return result.confidence > 0 ? result : null;
}

/**
 * Detect React Router v7 framework (with RSC support)
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectReactRouter(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.REACT_ROUTER,
    version: null,
    isSSR: false,
    hasRSC: false,
    confidence: 0,
    indicators: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.REACT_ROUTER];
  if (!signatures) return null;

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'script' && sig.pattern.test(html)) {
      result.indicators.push(`HTML: ${sig.pattern.source}`);
      result.confidence += 25;
    }
  }

  // Check URL patterns
  const allUrls = [
    ...Array.from(doc.querySelectorAll('script[src]')).map(s => s.src),
    ...Array.from(doc.querySelectorAll('link[href]')).map(l => l.href)
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

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script: ${pattern.source}`);
      result.confidence += 15;
    }
  }

  // Check for RSC (React Router v7 uses RSC)
  const rscResult = detectRSCIndicatorsGeneric(doc, html);
  if (rscResult.detected) {
    result.hasRSC = true;
    result.isSSR = true;
    result.indicators.push(...rscResult.indicators);
    result.confidence += 20;
  }

  // Try to extract version
  result.version = extractReactRouterVersion(html);
  if (result.version) {
    result.indicators.push(`Version: ${result.version}`);
    // Only v7+ has RSC
    const majorVersion = parseInt(result.version.split('.')[0], 10);
    if (majorVersion >= 7) {
      result.hasRSC = true;
    }
  }

  result.confidence = Math.min(100, result.confidence);
  return result.confidence > 0 ? result : null;
}

/**
 * Detect RedwoodJS framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectRedwood(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.REDWOOD,
    version: null,
    isSSR: false,
    hasRSC: false,
    confidence: 0,
    indicators: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.REDWOOD];
  if (!signatures) return null;

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'script' && sig.pattern.test(html)) {
      result.indicators.push(`HTML: ${sig.pattern.source}`);
      result.confidence += 25;
    }
  }

  // Check for __REDWOOD__ global
  if (html.includes('__REDWOOD__')) {
    result.indicators.push('__REDWOOD__ global');
    result.confidence += 30;
  }

  // Check URL patterns
  const allUrls = [
    ...Array.from(doc.querySelectorAll('script[src]')).map(s => s.src),
    ...Array.from(doc.querySelectorAll('link[href]')).map(l => l.href)
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

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script: ${pattern.source}`);
      result.confidence += 15;
    }
  }

  // RedwoodJS with RSC
  const rscResult = detectRSCIndicatorsGeneric(doc, html);
  if (rscResult.detected) {
    result.hasRSC = true;
    result.isSSR = true;
    result.indicators.push(...rscResult.indicators);
    result.confidence += 15;
  }

  // Try to extract version
  result.version = extractRedwoodVersion(html);
  if (result.version) {
    result.indicators.push(`Version: ${result.version}`);
  }

  result.confidence = Math.min(100, result.confidence);
  return result.confidence > 0 ? result : null;
}

/**
 * Detect RSC indicators generically
 * @param {Document} doc - Document to analyze
 * @param {string} html - HTML content
 * @returns {Object} - RSC detection result
 */
function detectRSCIndicatorsGeneric(doc, html) {
  const result = {
    detected: false,
    indicators: []
  };

  // Check for _rsc query parameter in links
  if (html.includes('_rsc=')) {
    result.detected = true;
    result.indicators.push('RSC query parameter detected');
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
      result.indicators.push('Flight protocol patterns');
      break;
    }
  }

  return result;
}

/**
 * Extract Waku version from HTML
 */
function extractWakuVersion(html) {
  const patterns = [
    /waku@([\d.]+)/,
    /"waku":\s*"[~^]?([\d.]+)"/
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) {
      return match[1];
    }
  }
  return null;
}

/**
 * Extract React Router version from HTML
 */
function extractReactRouterVersion(html) {
  const patterns = [
    /react-router@([\d.]+)/,
    /@react-router\/.*@([\d.]+)/,
    /"react-router":\s*"[~^]?([\d.]+)"/,
    /__reactRouterVersion.*["']([\d.]+)["']/
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) {
      return match[1];
    }
  }
  return null;
}

/**
 * Extract RedwoodJS version from HTML
 */
function extractRedwoodVersion(html) {
  const patterns = [
    /@redwoodjs\/.*@([\d.]+)/,
    /"@redwoodjs\/core":\s*"[~^]?([\d.]+)"/,
    /__REDWOOD__.*version.*["']([\d.]+)["']/
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match) {
      return match[1];
    }
  }
  return null;
}

export default {
  detectWaku,
  detectReactRouter,
  detectRedwood
};
