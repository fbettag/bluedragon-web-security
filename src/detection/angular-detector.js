/**
 * BlueDragon Web Security - Angular Detector
 * Detects Angular framework with SSR and version fingerprinting
 */

import { FRAMEWORKS } from '../shared/constants.js';
import { FRAMEWORK_SIGNATURES } from '../shared/framework-signatures.js';

/**
 * Detect Angular framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectAngular(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.ANGULAR,
    version: null,
    isSSR: false,
    hasUniversal: false,
    hasSSRModule: false,
    confidence: 0,
    indicators: [],
    components: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.ANGULAR];

  // Check ng-version attribute (most reliable)
  const ngVersionEl = doc.querySelector('[ng-version]');
  if (ngVersionEl) {
    result.version = ngVersionEl.getAttribute('ng-version');
    result.indicators.push(`ng-version: ${result.version}`);
    result.confidence += 40;
  }

  // Check for app-root (Angular default root component)
  const appRoot = doc.querySelector('app-root');
  if (appRoot) {
    result.indicators.push('app-root component');
    result.confidence += 25;
  }

  // Check for Angular-specific attributes
  const ngHostElements = doc.querySelectorAll('[class*="_nghost-"]');
  const ngContentElements = doc.querySelectorAll('[class*="_ngcontent-"]');

  if (ngHostElements.length > 0) {
    result.indicators.push(`_nghost- attributes (${ngHostElements.length})`);
    result.confidence += 20;
  }

  if (ngContentElements.length > 0) {
    result.indicators.push(`_ngcontent- attributes (${ngContentElements.length})`);
    result.confidence += 15;
  }

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script pattern: ${pattern.source}`);
      result.confidence += 10;
    }
  }

  // Check for Angular Universal / SSR
  const ssrIndicators = signatures.ssrIndicators;
  for (const indicator of ssrIndicators) {
    if (indicator.type === 'html' && indicator.pattern.test(html)) {
      result.isSSR = true;
      result.hasUniversal = true;
      result.indicators.push(`SSR: ${indicator.pattern.source}`);
      result.confidence += 10;
    }

    if (indicator.type === 'attribute') {
      if (doc.querySelector(indicator.selector)) {
        result.isSSR = true;
        result.indicators.push(`SSR attribute: ${indicator.selector}`);
        result.confidence += 10;
      }
    }

    if (indicator.type === 'script' && indicator.pattern.test(html)) {
      result.hasSSRModule = true;
      result.indicators.push(`SSR module: ${indicator.pattern.source}`);
      result.confidence += 10;
    }
  }

  // Check for ng-server-context (Angular 17+ SSR)
  if (html.includes('ng-server-context')) {
    result.isSSR = true;
    result.indicators.push('ng-server-context (Angular 17+ SSR)');
    result.confidence += 15;
  }

  // Check for serverApp attribute (Angular SSR marker)
  if (doc.querySelector('[serverApp]') || html.includes('serverApp')) {
    result.isSSR = true;
    result.indicators.push('serverApp marker');
    result.confidence += 10;
  }

  // Extract components
  result.components = extractAngularComponents(doc);
  if (result.components.length > 0) {
    result.indicators.push(`${result.components.length} components detected`);
  }

  // Try to extract version from scripts if not found
  if (!result.version) {
    result.version = extractAngularVersion(html);
    if (result.version) {
      result.indicators.push(`Version from scripts: ${result.version}`);
    }
  }

  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Extract Angular components from the page
 * @param {Document} doc - Document to analyze
 * @returns {string[]} - List of component selectors
 */
function extractAngularComponents(doc) {
  const components = new Set();

  // Look for custom elements (Angular components are typically kebab-case)
  const allElements = doc.querySelectorAll('*');
  for (const el of allElements) {
    const tagName = el.tagName.toLowerCase();
    // Custom elements contain a hyphen and aren't standard HTML
    if (tagName.includes('-') && !isStandardHtmlElement(tagName)) {
      components.add(tagName);
    }
  }

  return Array.from(components);
}

/**
 * Check if a tag name is a standard HTML element
 * @param {string} tagName - Tag name to check
 * @returns {boolean}
 */
function isStandardHtmlElement(tagName) {
  const standardElements = [
    'a', 'abbr', 'address', 'area', 'article', 'aside', 'audio',
    'b', 'base', 'bdi', 'bdo', 'blockquote', 'body', 'br', 'button',
    'canvas', 'caption', 'cite', 'code', 'col', 'colgroup',
    'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'div', 'dl', 'dt',
    'em', 'embed',
    'fieldset', 'figcaption', 'figure', 'footer', 'form',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html',
    'i', 'iframe', 'img', 'input', 'ins',
    'kbd', 'label', 'legend', 'li', 'link',
    'main', 'map', 'mark', 'math', 'menu', 'meta', 'meter',
    'nav', 'noscript',
    'object', 'ol', 'optgroup', 'option', 'output',
    'p', 'param', 'picture', 'pre', 'progress',
    'q', 'rp', 'rt', 'ruby',
    's', 'samp', 'script', 'section', 'select', 'slot', 'small', 'source', 'span', 'strong', 'style', 'sub', 'summary', 'sup', 'svg',
    'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track',
    'u', 'ul',
    'var', 'video',
    'wbr',
    // Web components that look like Angular
    'font-face', 'font-face-format', 'font-face-name', 'font-face-src', 'font-face-uri',
    'color-profile', 'font-face'
  ];

  return standardElements.includes(tagName);
}

/**
 * Extract Angular version from script content
 * @param {string} html - HTML content
 * @returns {string|null} - Version or null
 */
function extractAngularVersion(html) {
  const patterns = [
    /@angular\/core@([\d.]+)/,
    /"@angular\/core":\s*"[~^]?([\d.]+)"/,
    /angular[\\/]core@([\d.]+)/,
    /VERSION\s*=\s*new\s*Version\s*\(\s*['"]([^'"]+)['"]\s*\)/
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
 * Check if Angular version is vulnerable to race condition (CVE-2025-59052)
 * @param {string} version - Angular version
 * @param {boolean} isSSR - Whether SSR is detected
 * @returns {Object} - Vulnerability info
 */
export function checkRaceConditionVulnerable(version, isSSR) {
  if (!isSSR) {
    return {
      vulnerable: false,
      reason: 'SSR not detected - race condition only affects SSR apps'
    };
  }

  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Version not detected - manual verification required'
    };
  }

  // Vulnerable versions: 16.x through 21.0.0-next.3
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const majorVersion = parseInt(normalizedVersion.split('.')[0], 10);

  if (majorVersion >= 16 && majorVersion <= 21) {
    return {
      vulnerable: true,
      reason: `Angular ${version} SSR is vulnerable to race condition`,
      cve: 'CVE-2025-59052',
      severity: 'HIGH',
      note: 'Requires high-concurrency traffic to exploit'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

/**
 * Check if Angular version is vulnerable to SSRF (CVE-2025-62427)
 * @param {string} version - Angular version
 * @param {boolean} isSSR - Whether SSR is detected
 * @returns {Object} - Vulnerability info
 */
export function checkSSRFVulnerable(version, isSSR) {
  if (!isSSR) {
    return {
      vulnerable: false,
      reason: 'SSR not detected - SSRF only affects SSR apps'
    };
  }

  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Version not detected - manual verification required'
    };
  }

  // Vulnerable versions: 17.x through 21.x
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const majorVersion = parseInt(normalizedVersion.split('.')[0], 10);

  if (majorVersion >= 17 && majorVersion <= 21) {
    return {
      vulnerable: true,
      reason: `Angular ${version} SSR is vulnerable to URL SSRF`,
      cve: 'CVE-2025-62427',
      severity: 'HIGH',
      testVector: 'Double-slash path injection: //attacker.com/path'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

export default {
  detectAngular,
  checkRaceConditionVulnerable,
  checkSSRFVulnerable
};
