/**
 * BlueDragon Web Security - Constants
 * Core constants and configuration values
 */

// Severity levels for vulnerabilities
export const SEVERITY = {
  CRITICAL: 'CRITICAL',  // RCE, Auth bypass, Full compromise
  HIGH: 'HIGH',          // SSRF, XSS, Significant data exposure
  MEDIUM: 'MEDIUM',      // CSRF, Info leak, Partial access
  LOW: 'LOW',            // Missing headers, Minor misconfig
  INFO: 'INFO'           // Informational findings
};

// Severity colors for UI
export const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6'
};

// CVSS score ranges
export const CVSS_RANGES = {
  CRITICAL: { min: 9.0, max: 10.0 },
  HIGH: { min: 7.0, max: 8.9 },
  MEDIUM: { min: 4.0, max: 6.9 },
  LOW: { min: 0.1, max: 3.9 },
  INFO: { min: 0, max: 0 }
};

// Vulnerability types
export const VULN_TYPES = {
  RCE: 'Remote Code Execution',
  SSRF: 'Server-Side Request Forgery',
  XSS: 'Cross-Site Scripting',
  CSRF: 'Cross-Site Request Forgery',
  IDOR: 'Insecure Direct Object Reference',
  INFO_LEAK: 'Information Disclosure',
  PROTO_POLLUTION: 'Prototype Pollution',
  RACE_CONDITION: 'Race Condition',
  TEMPLATE_INJECTION: 'Template Injection',
  HEADER_INJECTION: 'Header Injection',
  OPEN_REDIRECT: 'Open Redirect',
  DOS: 'Denial of Service',
  MISCONFIG: 'Security Misconfiguration',
  AUTH_BYPASS: 'Authorization Bypass',
  PATH_TRAVERSAL: 'Path Traversal',
  SOURCE_EXPOSURE: 'Source Code Exposure'
};

// Framework identifiers
export const FRAMEWORKS = {
  NEXTJS: 'Next.js',
  REACT: 'React',
  ANGULAR: 'Angular',
  SVELTEKIT: 'SvelteKit',
  NUXT: 'Nuxt',
  VUE: 'Vue.js',
  REMIX: 'Remix',
  ASTRO: 'Astro',
  WAKU: 'Waku',
  REACT_ROUTER: 'React Router',
  REDWOOD: 'RedwoodJS',
  UNKNOWN: 'Unknown'
};

// Scan modes
export const SCAN_MODES = {
  PASSIVE: 'passive',      // Only detection, no probing
  ACTIVE: 'active',        // Full exploitation testing
  STEALTH: 'stealth'       // Minimal footprint scanning
};

// Scan depth levels
export const SCAN_DEPTH = {
  QUICK: 'quick',          // Framework detection + known CVEs only
  STANDARD: 'standard',    // All scanners, single page
  DEEP: 'deep',            // Multi-page crawl, all scanners
  FULL: 'full'             // Everything + fuzzing
};

// Default settings
export const DEFAULT_SETTINGS = {
  // Scanning
  autoScanEnabled: false,
  scanMode: SCAN_MODES.ACTIVE,
  scanDepth: SCAN_DEPTH.STANDARD,
  scanDelay: 3000,  // ms after page load

  // Safety
  respectRobotsTxt: false,
  maxRequestsPerSecond: 5,
  skipPaymentEndpoints: true,
  requireConfirmation: true,  // For state-changing exploits

  // Notifications
  notificationsEnabled: true,
  discordWebhookEnabled: false,
  discordWebhookUrl: '',

  // Collaborator / OOB
  collaboratorType: 'interactsh',  // 'burp', 'interactsh', 'custom'
  burpCollaboratorUrl: '',
  interactshServer: 'oast.fun',
  customWebhookUrl: '',

  // Proxy
  proxyEnabled: false,
  proxyHost: '127.0.0.1',
  proxyPort: 8080,
  proxyAuth: false,
  proxyUsername: '',
  proxyPassword: '',

  // History
  saveHistory: true,
  maxHistoryItems: 1000,

  // Export
  defaultExportFormat: 'json',  // 'json', 'nuclei', 'markdown'
  includePoC: true
};

// Rate limiting defaults
export const RATE_LIMITS = {
  requestsPerSecond: 5,
  requestsPerMinute: 100,
  burstSize: 10,
  cooldownMs: 1000
};

// Request timeouts
export const TIMEOUTS = {
  default: 10000,      // 10s
  probe: 5000,         // 5s for probes
  timing: 15000,       // 15s for timing attacks
  collaborator: 30000  // 30s for OOB callbacks
};

// Known vulnerable versions (for fingerprinting)
export const VULNERABLE_VERSIONS = {
  // React2Shell - CVE-2025-55182
  'react-server': ['19.0.0', '19.1.0', '19.1.1', '19.2.0'],
  'next': ['15.0.0', '15.0.1', '15.0.2', '15.0.3', '15.0.4', '16.0.0', '16.0.1', '16.0.2', '16.0.3', '16.0.4', '16.0.5', '16.0.6'],

  // Next.js Middleware Bypass - CVE-2025-29927
  'next-middleware': ['11.1.4-15.2.2'],

  // React DoS - CVE-2025-55184
  'react-dos': ['19.0.0-19.1.0'],

  // React DoS Incomplete Fix - CVE-2025-67779
  'react-dos-v2': ['19.1.0'],

  // React Source Code Exposure - CVE-2025-55183
  'react-source': ['19.0.0-19.1.0'],

  // Angular SSR Race - CVE-2025-59052
  '@angular/platform-server': ['16.0.0-21.0.0-next.3'],
  '@angular/ssr': ['16.0.0-21.0.0-next.3'],

  // Angular SSRF - CVE-2025-62427
  '@angular/ssr-ssrf': ['17.0.0-21.0.0'],

  // Angular XSRF Token Leak - CVE-2025-66035
  '@angular/xsrf': ['18.0.0-19.2.0'],

  // Angular Stored XSS - CVE-2025-66412
  '@angular/xss': ['18.0.0-19.2.0'],

  // SvelteKit CSRF - CVE-2023-29008
  '@sveltejs/kit': ['1.0.0-1.5.0'],

  // SvelteKit XSS - CVE-2024-53262
  '@sveltejs/kit-xss': ['2.0.0-2.8.0'],

  // SvelteKit searchParams XSS - CVE-2025-32388
  '@sveltejs/kit-params': ['2.0.0-2.20.6'],

  // Nuxt Dev - CVE-2023-3224
  'nuxt-dev': ['3.4.0', '3.4.1', '3.4.2', '3.4.3'],

  // Nuxt Devtools RCE - CVE-2024-23657
  'nuxt-devtools': ['0.1.0-1.3.8'],

  // Nuxt TestComponentWrapper RCE - CVE-2024-34344
  'nuxt-test': ['3.4.0-3.11.2'],

  // Vuetify Proto Pollution - CVE-2025-8083
  'vuetify': ['3.0.0-3.7.0'],

  // Waku RSC RCE - affects multiple versions
  'waku': ['0.1.0-0.22.0'],

  // React Router RSC - affects multiple versions
  'react-router': ['7.0.0-7.5.0'],

  // RedwoodSDK RSC - affects multiple versions
  'redwoodjs': ['0.1.0-1.0.0']
};

// CVE database
export const CVE_DATABASE = {
  'CVE-2025-55182': {
    name: 'React2Shell',
    type: VULN_TYPES.RCE,
    severity: SEVERITY.CRITICAL,
    cvss: 10.0,
    frameworks: [FRAMEWORKS.REACT, FRAMEWORKS.NEXTJS, FRAMEWORKS.WAKU, FRAMEWORKS.REACT_ROUTER, FRAMEWORKS.REDWOOD],
    description: 'Flight protocol deserialization leads to unauthenticated RCE',
    affectedVersions: VULNERABLE_VERSIONS['react-server'],
    scanner: 'react2shell'
  },
  'CVE-2025-29927': {
    name: 'Next.js Middleware Bypass',
    type: VULN_TYPES.AUTH_BYPASS,
    severity: SEVERITY.CRITICAL,
    cvss: 9.1,
    frameworks: [FRAMEWORKS.NEXTJS],
    description: 'x-middleware-subrequest header bypasses middleware authorization checks',
    affectedVersions: VULNERABLE_VERSIONS['next-middleware'],
    scanner: 'middleware-bypass'
  },
  'CVE-2025-55183': {
    name: 'React Source Code Exposure',
    type: VULN_TYPES.SOURCE_EXPOSURE,
    severity: SEVERITY.MEDIUM,
    cvss: 5.3,
    frameworks: [FRAMEWORKS.REACT, FRAMEWORKS.NEXTJS],
    description: 'Server source code exposed via RSC Flight protocol response',
    affectedVersions: VULNERABLE_VERSIONS['react-source'],
    scanner: 'source-exposure'
  },
  'CVE-2025-55184': {
    name: 'React DoS via Infinite Loop',
    type: VULN_TYPES.DOS,
    severity: SEVERITY.HIGH,
    cvss: 7.5,
    frameworks: [FRAMEWORKS.REACT, FRAMEWORKS.NEXTJS],
    description: 'Malformed RSC payload causes infinite loop and server hang',
    affectedVersions: VULNERABLE_VERSIONS['react-dos'],
    scanner: 'react-dos'
  },
  'CVE-2025-67779': {
    name: 'React DoS Incomplete Fix',
    type: VULN_TYPES.DOS,
    severity: SEVERITY.HIGH,
    cvss: 7.5,
    frameworks: [FRAMEWORKS.REACT, FRAMEWORKS.NEXTJS],
    description: 'Incomplete fix for CVE-2025-55184, still exploitable via different payload',
    affectedVersions: VULNERABLE_VERSIONS['react-dos-v2'],
    scanner: 'react-dos-v2'
  },
  'CVE-2024-34351': {
    name: 'Server Action SSRF',
    type: VULN_TYPES.SSRF,
    severity: SEVERITY.HIGH,
    cvss: 7.5,
    frameworks: [FRAMEWORKS.NEXTJS],
    description: 'Host header injection in Server Actions allows SSRF',
    scanner: 'server-action-ssrf'
  },
  'CVE-2024-47831': {
    name: 'Image Optimization DoS',
    type: VULN_TYPES.DOS,
    severity: SEVERITY.MEDIUM,
    cvss: 5.3,
    frameworks: [FRAMEWORKS.NEXTJS],
    description: 'Image optimization endpoint vulnerable to resource exhaustion',
    scanner: 'image-dos'
  },
  'CVE-2025-59052': {
    name: 'Angular SSR Race Condition',
    type: VULN_TYPES.RACE_CONDITION,
    severity: SEVERITY.HIGH,
    cvss: 7.1,
    frameworks: [FRAMEWORKS.ANGULAR],
    description: 'Global Platform Injector race condition leaks user data',
    scanner: 'race-condition'
  },
  'CVE-2025-62427': {
    name: 'Angular SSR SSRF',
    type: VULN_TYPES.SSRF,
    severity: SEVERITY.HIGH,
    cvss: 8.7,
    frameworks: [FRAMEWORKS.ANGULAR],
    description: 'Double-slash URL path injection leads to SSRF',
    scanner: 'url-ssrf'
  },
  'CVE-2025-66035': {
    name: 'Angular XSRF Token Leakage',
    type: VULN_TYPES.INFO_LEAK,
    severity: SEVERITY.MEDIUM,
    cvss: 5.3,
    frameworks: [FRAMEWORKS.ANGULAR],
    description: 'XSRF token exposed via state transfer in SSR applications',
    affectedVersions: VULNERABLE_VERSIONS['@angular/xsrf'],
    scanner: 'xsrf-leak'
  },
  'CVE-2025-66412': {
    name: 'Angular Stored XSS',
    type: VULN_TYPES.XSS,
    severity: SEVERITY.MEDIUM,
    cvss: 6.1,
    frameworks: [FRAMEWORKS.ANGULAR],
    description: 'Stored XSS via SSR hydration state manipulation',
    affectedVersions: VULNERABLE_VERSIONS['@angular/xss'],
    scanner: 'angular-xss'
  },
  'CVE-2023-29008': {
    name: 'SvelteKit CSRF Bypass',
    type: VULN_TYPES.CSRF,
    severity: SEVERITY.MEDIUM,
    cvss: 6.5,
    frameworks: [FRAMEWORKS.SVELTEKIT],
    description: 'Content-Type case sensitivity bypasses CSRF protection',
    scanner: 'csrf-bypass'
  },
  'CVE-2024-53262': {
    name: 'SvelteKit Template XSS',
    type: VULN_TYPES.XSS,
    severity: SEVERITY.MEDIUM,
    cvss: 6.1,
    frameworks: [FRAMEWORKS.SVELTEKIT],
    description: 'Error page template injection allows XSS',
    scanner: 'template-injection'
  },
  'CVE-2025-32388': {
    name: 'SvelteKit searchParams XSS',
    type: VULN_TYPES.XSS,
    severity: SEVERITY.MEDIUM,
    cvss: 6.1,
    frameworks: [FRAMEWORKS.SVELTEKIT],
    description: 'URL searchParams passed to goto() enables XSS',
    affectedVersions: VULNERABLE_VERSIONS['@sveltejs/kit-params'],
    scanner: 'searchparams-xss'
  },
  'CVE-2023-3224': {
    name: 'Nuxt Dev Server Injection',
    type: VULN_TYPES.RCE,
    severity: SEVERITY.CRITICAL,
    cvss: 9.8,
    frameworks: [FRAMEWORKS.NUXT],
    description: 'Development server code injection via URL',
    scanner: 'dev-injection'
  },
  'CVE-2024-23657': {
    name: 'Nuxt Devtools RCE',
    type: VULN_TYPES.RCE,
    severity: SEVERITY.CRITICAL,
    cvss: 9.8,
    frameworks: [FRAMEWORKS.NUXT],
    description: 'Path traversal in Nuxt Devtools leads to arbitrary file read and RCE',
    affectedVersions: VULNERABLE_VERSIONS['nuxt-devtools'],
    scanner: 'devtools-rce'
  },
  'CVE-2024-34344': {
    name: 'Nuxt TestComponentWrapper RCE',
    type: VULN_TYPES.RCE,
    severity: SEVERITY.CRITICAL,
    cvss: 9.8,
    frameworks: [FRAMEWORKS.NUXT],
    description: 'TestComponentWrapper exposed in production allows arbitrary component rendering',
    affectedVersions: VULNERABLE_VERSIONS['nuxt-test'],
    scanner: 'testcomponent-rce'
  },
  'CVE-2025-8083': {
    name: 'Vuetify Prototype Pollution',
    type: VULN_TYPES.PROTO_POLLUTION,
    severity: SEVERITY.HIGH,
    cvss: 7.5,
    frameworks: [FRAMEWORKS.VUE],
    description: 'mergeDeep function allows prototype pollution',
    scanner: 'prototype-pollution'
  }
};

// Domains to skip during scanning (noisy, rarely buggy)
export const SKIP_DOMAINS = [
  // Analytics
  'google-analytics.com',
  'googletagmanager.com',
  'hotjar.com',
  'segment.com',
  'mixpanel.com',
  'amplitude.com',
  'fullstory.com',
  'heap.io',
  'plausible.io',

  // CDNs
  'cloudflare.com',
  'cloudfront.net',
  'fastly.net',
  'akamaized.net',
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',

  // Social
  'facebook.com',
  'twitter.com',
  'linkedin.com',
  'instagram.com',
  'tiktok.com',

  // Google services
  'googleapis.com',
  'gstatic.com',
  'google.com',

  // Common third parties
  'stripe.com',
  'paypal.com',
  'braintree-api.com',
  'intercom.io',
  'zendesk.com',
  'crisp.chat',
  'drift.com',
  'hubspot.com',
  'salesforce.com',

  // Auth providers
  'auth0.com',
  'okta.com',
  'clerk.dev',

  // Browser extensions
  'chrome-extension://',
  'moz-extension://'
];

// Message types for extension communication
export const MESSAGE_TYPES = {
  // Content -> Background
  FRAMEWORK_DETECTED: 'DRAGON_FRAMEWORK_DETECTED',
  SCAN_REQUEST: 'DRAGON_SCAN_REQUEST',
  VULN_FOUND: 'DRAGON_VULN_FOUND',
  SCAN_COMPLETE: 'DRAGON_SCAN_COMPLETE',
  EXPLOIT_RESULT: 'DRAGON_EXPLOIT_RESULT',

  // Background -> Content
  START_SCAN: 'DRAGON_START_SCAN',
  STOP_SCAN: 'DRAGON_STOP_SCAN',
  GET_STATUS: 'DRAGON_GET_STATUS',

  // Background -> Popup
  STATUS_UPDATE: 'DRAGON_STATUS_UPDATE',
  RESULTS_UPDATE: 'DRAGON_RESULTS_UPDATE',

  // Popup -> Background
  MANUAL_SCAN: 'DRAGON_MANUAL_SCAN',
  DEEP_SCAN: 'DRAGON_DEEP_SCAN',
  EXPORT_REQUEST: 'DRAGON_EXPORT_REQUEST',
  GET_HISTORY: 'DRAGON_GET_HISTORY',
  CLEAR_HISTORY: 'DRAGON_CLEAR_HISTORY',

  // Injected -> Content
  NETWORK_CAPTURE: 'DRAGON_NETWORK_CAPTURE',
  DOM_FINDING: 'DRAGON_DOM_FINDING'
};

// Export everything as default too
export default {
  SEVERITY,
  SEVERITY_COLORS,
  CVSS_RANGES,
  VULN_TYPES,
  FRAMEWORKS,
  SCAN_MODES,
  SCAN_DEPTH,
  DEFAULT_SETTINGS,
  RATE_LIMITS,
  TIMEOUTS,
  VULNERABLE_VERSIONS,
  CVE_DATABASE,
  SKIP_DOMAINS,
  MESSAGE_TYPES
};
