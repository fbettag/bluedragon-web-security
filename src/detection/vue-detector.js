/**
 * BlueDragon Web Security - Vue.js/Nuxt Detector
 * Detects Vue.js and Nuxt frameworks with version fingerprinting
 */

import { FRAMEWORKS } from '../shared/constants.js';
import { FRAMEWORK_SIGNATURES, VUETIFY_SIGNATURES } from '../shared/framework-signatures.js';

/**
 * Detect Nuxt framework
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectNuxt(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.NUXT,
    version: null,
    nuxtVersion: null,
    vueVersion: null,
    isSSR: false,
    isNuxt3: false,
    isDev: false,
    confidence: 0,
    indicators: [],
    modules: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.NUXT];

  // Check for __NUXT__ global
  if (html.includes('__NUXT__')) {
    result.indicators.push('__NUXT__ global');
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

  // Check for #__nuxt element
  const nuxtRoot = doc.querySelector('#__nuxt');
  if (nuxtRoot) {
    result.indicators.push('#__nuxt root element');
    result.confidence += 25;
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
    if (indicator.type === 'script' && indicator.pattern.test(html)) {
      result.isSSR = true;
      result.indicators.push(`SSR: ${indicator.pattern.source}`);
      result.confidence += 10;
    }

    if (indicator.type === 'html' && indicator.pattern.test(html)) {
      result.isSSR = true;
      result.indicators.push(`SSR marker: ${indicator.pattern.source}`);
      result.confidence += 10;
    }
  }

  // Check for data-server-rendered attribute
  if (doc.querySelector('[data-server-rendered]') || html.includes('data-server-rendered')) {
    result.isSSR = true;
    result.indicators.push('data-server-rendered attribute');
    result.confidence += 15;
  }

  // Detect Nuxt 3 vs Nuxt 2
  if (html.includes('_payload.json') || html.includes('$fetch')) {
    result.isNuxt3 = true;
    result.indicators.push('Nuxt 3 detected');
  }

  // Check for dev mode
  result.isDev = detectNuxtDevMode(doc, html);
  if (result.isDev) {
    result.indicators.push('Development mode detected (CVE-2023-3224 risk)');
    result.confidence += 5;
  }

  // Extract versions
  const versions = extractNuxtVersions(html);
  result.nuxtVersion = versions.nuxt;
  result.vueVersion = versions.vue;

  if (result.nuxtVersion) {
    result.version = result.nuxtVersion;
    result.indicators.push(`Nuxt version: ${result.nuxtVersion}`);
  }
  if (result.vueVersion) {
    result.indicators.push(`Vue version: ${result.vueVersion}`);
  }

  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Detect generic Vue.js (when not Nuxt)
 * @param {Document} doc - Document to analyze
 * @param {string} html - Full HTML content
 * @param {Map} scriptContents - Script contents map
 * @param {Object} options - Detection options
 * @returns {Object|null} - Detection result
 */
export async function detectVue(doc, html, scriptContents, options = {}) {
  const result = {
    framework: FRAMEWORKS.VUE,
    version: null,
    isSSR: false,
    hasVuetify: false,
    vuetifyVersion: null,
    hasPinia: false,
    hasVuex: false,
    confidence: 0,
    indicators: []
  };

  const signatures = FRAMEWORK_SIGNATURES[FRAMEWORKS.VUE];

  // Check HTML markers
  for (const sig of signatures.signatures.html) {
    if (sig.type === 'attribute') {
      if (doc.querySelector(sig.selector)) {
        result.indicators.push(`Attribute: ${sig.selector}`);
        result.confidence += 20;
      }
    }
  }

  // Check for data-v- scoped style attributes
  const scopedElements = doc.querySelectorAll('[class*="data-v-"]');
  if (scopedElements.length > 0 || html.includes('data-v-')) {
    result.indicators.push('Vue scoped styles (data-v-)');
    result.confidence += 25;
  }

  // Check script patterns
  for (const pattern of signatures.signatures.scripts) {
    if (pattern.test(html)) {
      result.indicators.push(`Script: ${pattern.source}`);
      result.confidence += 10;
    }
  }

  // Check for __VUE__ global reference
  if (html.includes('__VUE__')) {
    result.indicators.push('__VUE__ global');
    result.confidence += 20;
  }

  // Check for Vuetify
  const vuetifyResult = detectVuetify(doc, html);
  if (vuetifyResult.detected) {
    result.hasVuetify = true;
    result.vuetifyVersion = vuetifyResult.version;
    result.indicators.push('Vuetify detected');
    if (vuetifyResult.version) {
      result.indicators.push(`Vuetify version: ${vuetifyResult.version}`);
    }
  }

  // Check for state management
  if (html.includes('pinia') || html.includes('__pinia')) {
    result.hasPinia = true;
    result.indicators.push('Pinia state management');
  }

  if (html.includes('vuex') || html.includes('__VUEX__')) {
    result.hasVuex = true;
    result.indicators.push('Vuex state management');
  }

  // Extract Vue version
  result.version = extractVueVersion(html);
  if (result.version) {
    result.indicators.push(`Vue version: ${result.version}`);
  }

  result.confidence = Math.min(100, result.confidence);

  return result.confidence > 0 ? result : null;
}

/**
 * Detect Nuxt development mode
 * @param {Document} doc - Document to analyze
 * @param {string} html - HTML content
 * @returns {boolean} - Whether dev mode is detected
 */
function detectNuxtDevMode(doc, html) {
  // Check for dev indicators
  const devIndicators = [
    '/_nuxt/@vite/',
    '/__nuxt_devtools__',
    'nuxt-devtools',
    'process.dev',
    '__NUXT_DEV__',
    'localhost:3000',
    'localhost:24678',  // Nuxt dev server websocket
    '/_loading/',
    '__DEV__'
  ];

  for (const indicator of devIndicators) {
    if (html.includes(indicator)) {
      return true;
    }
  }

  // Check for HMR (Hot Module Replacement) scripts
  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const src = script.src || '';
    if (src.includes('@vite/client') || src.includes('hmr')) {
      return true;
    }
  }

  return false;
}

/**
 * Detect Vuetify component library
 * @param {Document} doc - Document to analyze
 * @param {string} html - HTML content
 * @returns {Object} - Vuetify detection result
 */
function detectVuetify(doc, html) {
  const result = {
    detected: false,
    version: null
  };

  // Check for Vuetify markers
  for (const pattern of VUETIFY_SIGNATURES.scripts) {
    if (pattern.test(html)) {
      result.detected = true;
      break;
    }
  }

  // Check for Vuetify components
  const vuetifyComponents = ['v-app', 'v-main', 'v-container', 'v-btn', 'v-card'];
  for (const comp of vuetifyComponents) {
    if (doc.querySelector(comp)) {
      result.detected = true;
      break;
    }
  }

  // Extract version
  if (result.detected) {
    for (const vp of VUETIFY_SIGNATURES.versionPatterns) {
      const match = html.match(vp.pattern);
      if (match) {
        result.version = match[1];
        break;
      }
    }
  }

  return result;
}

/**
 * Extract Nuxt and Vue versions from HTML
 * @param {string} html - HTML content
 * @returns {Object} - Extracted versions
 */
function extractNuxtVersions(html) {
  const result = { nuxt: null, vue: null };

  // Nuxt version patterns
  const nuxtPatterns = [
    /"nuxt":\s*"[~^]?([\d.]+)"/,
    /nuxt@([\d.]+)/,
    /__NUXT__.*version.*["']([\d.]+)["']/
  ];

  for (const pattern of nuxtPatterns) {
    const match = html.match(pattern);
    if (match) {
      result.nuxt = match[1];
      break;
    }
  }

  // Vue version patterns
  result.vue = extractVueVersion(html);

  return result;
}

/**
 * Extract Vue.js version from HTML
 * @param {string} html - HTML content
 * @returns {string|null} - Version or null
 */
function extractVueVersion(html) {
  const patterns = [
    /"vue":\s*"[~^]?([\d.]+)"/,
    /vue@([\d.]+)/,
    /Vue\.version\s*=\s*["']([\d.]+)["']/
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
 * Check if Nuxt version is vulnerable to dev server injection (CVE-2023-3224)
 * @param {string} version - Nuxt version
 * @param {boolean} isDev - Whether dev mode is detected
 * @returns {Object} - Vulnerability info
 */
export function checkDevInjectionVulnerable(version, isDev) {
  if (!isDev) {
    return {
      vulnerable: false,
      reason: 'Development mode not detected - this CVE only affects dev server'
    };
  }

  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Version not detected but dev mode is active - manual verification required',
      note: 'Check if running Nuxt 3.4.0-3.4.3'
    };
  }

  // Vulnerable versions: 3.4.0 to 3.4.3
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  if (parts[0] === 3 && parts[1] === 4 && parts[2] >= 0 && parts[2] <= 3) {
    return {
      vulnerable: true,
      reason: `Nuxt ${version} dev server is vulnerable to code injection`,
      cve: 'CVE-2023-3224',
      severity: 'CRITICAL',
      note: 'This vulnerability allows RCE via the dev server error overlay'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

/**
 * Check if Vuetify version is vulnerable to prototype pollution (CVE-2025-8083)
 * @param {string} version - Vuetify version
 * @returns {Object} - Vulnerability info
 */
export function checkPrototypePollutionVulnerable(version) {
  if (!version) {
    return {
      vulnerable: 'unknown',
      reason: 'Vuetify version not detected - manual verification required'
    };
  }

  // Vulnerable versions: 3.0.0 to 3.7.0
  const normalizedVersion = version.replace(/[~^]/, '').split('-')[0];
  const parts = normalizedVersion.split('.').map(p => parseInt(p, 10));

  if (parts[0] === 3 && parts[1] >= 0 && parts[1] <= 7) {
    return {
      vulnerable: true,
      reason: `Vuetify ${version} is vulnerable to prototype pollution`,
      cve: 'CVE-2025-8083',
      severity: 'HIGH',
      note: 'mergeDeep function allows __proto__ pollution'
    };
  }

  return {
    vulnerable: false,
    reason: `Version ${version} is outside vulnerable range`
  };
}

export default {
  detectNuxt,
  detectVue,
  checkDevInjectionVulnerable,
  checkPrototypePollutionVulnerable
};
