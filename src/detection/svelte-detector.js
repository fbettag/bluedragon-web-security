/**
 * BlueDragon Web Security - SvelteKit Detector
 * Detects SvelteKit framework with version fingerprinting
 */

import { FRAMEWORKS } from '../shared/constants.js';
import { FRAMEWORK_SIGNATURES } from '../shared/framework-signatures.js';

/**
 * Detect SvelteKit framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectSvelteKit(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.SVELTEKIT,
    version: null,
    svelteVersion: null,
    isSSR: false,
    confidence: 0,
    indicators: [],
    routes: [],
    hasFormActions: false
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.SVELTEKIT];

  // Check for __sveltekit marker
  if (html.includes('__sveltekit')) {
    result.indicators.push('__sveltekit global');
    result.confidence += 35;
  }

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'script' && sig.pattern.test(html)) {
      result.indicators.push(`Script: ${sig.pattern.source}`);
      result.confidence += 15;
    }
    if (sig.type === 'attribute') {
      if (doc.querySelector(sig.selector)) {
        result.indicators.push(`Attribute: ${sig.selector}`);
        result.confidence += 20;
      }
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

  // Check for SSR indicators
  for (const indicator of signatures.ssrIndicators) {
    if (indicator.type === 'html' && indicator.pattern.test(html)) {
      result.isSSR = true;
      result.indicators.push(`SSR: ${indicator.pattern.source}`);
      result.confidence += 10;
    }

    if (indicator.type === 'script' && indicator.pattern.test(html)) {
      result.isSSR = true;
      result.indicators.push(`SSR script: ${indicator.pattern.source}`);
      result.confidence += 10;
    }
  }

  // Check for data-sveltekit-hydrate (SSR marker)
  const hydrateElements = doc.querySelectorAll('[data-sveltekit-hydrate]');
  if (hydrateElements.length > 0) {
    result.isSSR = true;
    result.indicators.push('data-sveltekit-hydrate attribute');
    result.confidence += 20;
  }

  // Check for SvelteKit form actions
  const formActions = doc.querySelectorAll('form[action^="?/"]');
  if (formActions.length > 0) {
    result.hasFormActions = true;
    result.indicators.push(`${formActions.length} form actions detected`);
    result.confidence += 10;
  }

  // Extract routes from prefetch hints
  result.routes = extractSvelteKitRoutes(doc);
  if (result.routes.length > 0) {
    result.indicators.push(`${result.routes.length} routes discovered`);
  }

  // Try to extract version
  result.version = extractSvelteKitVersion(html);
  result.svelteVersion = extractSvelteVersion(html);

  if (result.version) {
    result.indicators.push(`SvelteKit version: ${result.version}`);
  }
  if (result.svelteVersion) {
    result.indicators.push(`Svelte version: ${result.svelteVersion}`);
  }

  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Extract SvelteKit routes from the page
 * @param {Document} doc - Document to analyze
 * @returns {string[]} - List of discovered routes
 */
function extractSvelteKitRoutes(doc) {
  const routes = new Set();

  // Check prefetch links
  const prefetchLinks = doc.querySelectorAll('[data-sveltekit-prefetch]');
  for (const link of prefetchLinks) {
    const href = link.getAttribute('href');
    if (href) {
      routes.add(href);
    }
  }

  // Check regular links that look like routes
  const links = doc.querySelectorAll('a[href^="/"]');
  for (const link of links) {
    const href = link.getAttribute('href');
    if (href && !href.includes('.') && !href.startsWith('/_app/')) {
      routes.add(href);
    }
  }

  return Array.from(routes);
}

/**
 * Extract SvelteKit version from HTML content
 * @param {string} html - HTML content
 * @returns {string|null} - Version or null
 */
function extractSvelteKitVersion(html) {
  const patterns = [
    /@sveltejs\/kit@([\d.]+)/,
    /"@sveltejs\/kit":\s*"[~^]?([\d.]+)"/,
    /sveltekit[\/\\]package\.json.*"version":\s*"([^"]+)"/
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
 * Extract Svelte version from HTML content
 * @param {string} html - HTML content
 * @returns {string|null} - Version or null
 */
function extractSvelteVersion(html) {
  const patterns = [
    /svelte@([\d.]+)/,
    /"svelte":\s*"[~^]?([\d.]+)"/
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
 * Check if SvelteKit version is vulnerable to CSRF bypass (CVE-2023-29008)
 * @param {string} version - SvelteKit version
 * @returns {Object} - Vulnerability info
 */
export function checkCSRFBypassVulnerable(version) {
  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Version not detected - manual verification required'
    };
  }

  // Vulnerable versions: 1.0.0 to 1.5.0
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Check if version is 1.x and below 1.5.1
  if (parts[0] === 1 && (parts[1] < 5 || (parts[1] === 5 && parts[2] === 0))) {
    return {
      vulnerable: true,
      reason: `SvelteKit ${version} is vulnerable to CSRF bypass`,
      cve: 'CVE-2023-29008',
      severity: 'MEDIUM',
      testVector: 'Mixed-case Content-Type header (e.g., text/plaiN)'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

/**
 * Check if SvelteKit version is vulnerable to template XSS (CVE-2024-53262)
 * @param {string} version - SvelteKit version
 * @returns {Object} - Vulnerability info
 */
export function checkTemplateXSSVulnerable(version) {
  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Version not detected - manual verification required'
    };
  }

  // Vulnerable versions: 2.0.0 to 2.8.0
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  // Check if version is 2.x and below 2.8.1
  if (parts[0] === 2 && parts[1] <= 8) {
    return {
      vulnerable: true,
      reason: `SvelteKit ${version} may be vulnerable to error template XSS`,
      cve: 'CVE-2024-53262',
      severity: 'MEDIUM',
      note: 'Requires application to throw errors with user-controlled content'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

export default {
  detectSvelteKit,
  checkCSRFBypassVulnerable,
  checkTemplateXSSVulnerable
};
