/**
 * BlueDragon Web Security - Framework Signatures
 * Detection patterns for identifying frontend frameworks
 */

import { FRAMEWORKS } from './constants.js';

/**
 * Framework detection signatures
 * Each framework has multiple detection methods for accuracy
 */
export const FRAMEWORK_SIGNATURES = {
  [FRAMEWORKS.NEXTJS]: {
    name: 'Next.js',
    priority: 1,  // Check first (most common SSR framework)
    signatures: {
      // HTML markers
      html: [
        { type: 'attribute', selector: '[data-nextjs-scroll-focus-boundary]' },
        { type: 'script', pattern: /__NEXT_DATA__/ },
        { type: 'script', pattern: /_next\/static/ },
        { type: 'link', pattern: /_next\/static\/css/ }
      ],
      // URL patterns
      urls: [
        /\/_next\//,
        /\/_next\/static\//,
        /\/_next\/image/
      ],
      // Response headers
      headers: [
        { name: 'x-powered-by', pattern: /Next\.js/i },
        { name: 'x-nextjs-cache', pattern: /.+/ },
        { name: 'x-nextjs-matched-path', pattern: /.+/ }
      ],
      // Script content patterns
      scripts: [
        /__NEXT_DATA__/,
        /next\/router/,
        /next\/link/,
        /_next\/static\/chunks/
      ],
      // Request headers (for intercepted requests)
      requestHeaders: [
        { name: 'Next-Action', pattern: /.+/ },
        { name: 'Next-Router-State-Tree', pattern: /.+/ },
        { name: 'RSC', pattern: /1/ }
      ]
    },
    // Version extraction patterns
    versionPatterns: [
      { source: 'html', pattern: /"next":"([\d.]+)"/ },
      { source: 'script', pattern: /Next\.js\s+([\d.]+)/ },
      { source: 'header', name: 'x-powered-by', pattern: /Next\.js\s*([\d.]+)?/ },
      { source: 'buildId', pattern: /_next\/static\/([^/]+)\// }
    ],
    // SSR indicators (vs static export)
    ssrIndicators: [
      { type: 'header', name: 'x-nextjs-cache' },
      { type: 'header', name: 'x-middleware-invoke' },
      { type: 'script', pattern: /__NEXT_DATA__.*"rsc":/ },
      { type: 'request', pattern: /\?_rsc=/ }
    ]
  },

  [FRAMEWORKS.REACT]: {
    name: 'React',
    priority: 5,  // Check after Next.js (Next includes React)
    signatures: {
      html: [
        { type: 'attribute', selector: '[data-reactroot]' },
        { type: 'attribute', selector: '[data-react-helmet]' },
        { type: 'comment', pattern: /react-text/ }
      ],
      urls: [],
      headers: [],
      scripts: [
        /React\.createElement/,
        /react-dom/,
        /__REACT_DEVTOOLS_GLOBAL_HOOK__/,
        /jsx-runtime/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'script', pattern: /React\.version\s*=\s*["']([\d.]+)["']/ },
      { source: 'script', pattern: /"react":\s*"[~^]?([\d.]+)"/ }
    ],
    ssrIndicators: []
  },

  [FRAMEWORKS.ANGULAR]: {
    name: 'Angular',
    priority: 2,
    signatures: {
      html: [
        { type: 'attribute', selector: '[ng-version]' },
        { type: 'attribute', selector: 'app-root' },
        { type: 'attribute', selector: '[_nghost-]' },
        { type: 'attribute', selector: '[_ngcontent-]' },
        { type: 'tag', name: 'app-root' }
      ],
      urls: [
        /\/main\.[a-f0-9]+\.js/,
        /\/polyfills\.[a-f0-9]+\.js/,
        /\/runtime\.[a-f0-9]+\.js/
      ],
      headers: [],
      scripts: [
        /@angular\/core/,
        /ng\.probe/,
        /platformBrowserDynamic/,
        /ngDevMode/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'html', attribute: 'ng-version', pattern: /([\d.]+)/ },
      { source: 'script', pattern: /@angular\/core@([\d.]+)/ }
    ],
    ssrIndicators: [
      { type: 'html', pattern: /ng-server-context/ },
      { type: 'attribute', selector: '[serverApp]' },
      { type: 'script', pattern: /@angular\/platform-server/ },
      { type: 'script', pattern: /@angular\/ssr/ }
    ]
  },

  [FRAMEWORKS.SVELTEKIT]: {
    name: 'SvelteKit',
    priority: 3,
    signatures: {
      html: [
        { type: 'attribute', selector: '[data-sveltekit-hydrate]' },
        { type: 'attribute', selector: '[data-sveltekit-prefetch]' },
        { type: 'script', pattern: /__sveltekit/ }
      ],
      urls: [
        /\/_app\/immutable\//,
        /\/_app\/version\.json/,
        /\.svelte-kit\//
      ],
      headers: [],
      scripts: [
        /__sveltekit/,
        /svelte.*hydrate/,
        /@sveltejs\/kit/,
        /start\s*\(\s*\{.*hydrate/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'script', pattern: /@sveltejs\/kit@([\d.]+)/ },
      { source: 'script', pattern: /svelte['"]\s*:\s*['"]([\d.]+)['"]/ }
    ],
    ssrIndicators: [
      { type: 'html', pattern: /data-sveltekit-hydrate/ },
      { type: 'script', pattern: /__sveltekit.*\.server/ }
    ]
  },

  [FRAMEWORKS.NUXT]: {
    name: 'Nuxt',
    priority: 4,
    signatures: {
      html: [
        { type: 'attribute', selector: '[data-n-head]' },
        { type: 'attribute', selector: '#__nuxt' },
        { type: 'attribute', selector: '#__layout' },
        { type: 'script', pattern: /__NUXT__/ }
      ],
      urls: [
        /\/_nuxt\//,
        /\/_payload\.json/
      ],
      headers: [
        { name: 'x-powered-by', pattern: /Nuxt/i }
      ],
      scripts: [
        /__NUXT__/,
        /nuxt\.config/,
        /$nuxt/,
        /NuxtLink/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'html', pattern: /"nuxt":\s*"[~^]?([\d.]+)"/ },
      { source: 'script', pattern: /nuxt@([\d.]+)/ }
    ],
    ssrIndicators: [
      { type: 'script', pattern: /__NUXT__.*serverRendered.*true/ },
      { type: 'html', pattern: /data-server-rendered/ }
    ]
  },

  [FRAMEWORKS.VUE]: {
    name: 'Vue.js',
    priority: 6,  // Check after Nuxt
    signatures: {
      html: [
        { type: 'attribute', selector: '[data-v-]' },
        { type: 'attribute', selector: '#app[data-v-app]' },
        { type: 'attribute', selector: '[v-cloak]' }
      ],
      urls: [],
      headers: [],
      scripts: [
        /Vue\.version/,
        /createApp/,
        /__VUE__/,
        /vue-router/,
        /vuex/,
        /pinia/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'script', pattern: /Vue\.version\s*=\s*["']([\d.]+)["']/ },
      { source: 'script', pattern: /"vue":\s*"[~^]?([\d.]+)"/ }
    ],
    ssrIndicators: []
  },

  [FRAMEWORKS.REMIX]: {
    name: 'Remix',
    priority: 7,
    signatures: {
      html: [
        { type: 'script', pattern: /__remixContext/ },
        { type: 'script', pattern: /__remixManifest/ }
      ],
      urls: [
        /\/build\//,
        /\/_data/
      ],
      headers: [
        { name: 'x-remix-response', pattern: /yes/ }
      ],
      scripts: [
        /__remixContext/,
        /@remix-run/,
        /RemixBrowser/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'script', pattern: /@remix-run\/.*@([\d.]+)/ }
    ],
    ssrIndicators: [
      { type: 'header', name: 'x-remix-response' }
    ]
  },

  [FRAMEWORKS.ASTRO]: {
    name: 'Astro',
    priority: 8,
    signatures: {
      html: [
        { type: 'attribute', selector: '[data-astro-cid-]' },
        { type: 'script', pattern: /astro:/ }
      ],
      urls: [
        /\/_astro\//
      ],
      headers: [],
      scripts: [
        /astro:/,
        /@astrojs/
      ],
      requestHeaders: []
    },
    versionPatterns: [
      { source: 'html', pattern: /astro@([\d.]+)/ }
    ],
    ssrIndicators: []
  },

  [FRAMEWORKS.WAKU]: {
    name: 'Waku',
    priority: 9,
    signatures: {
      html: [
        { type: 'script', pattern: /__WAKU_/ },
        { type: 'script', pattern: /waku/ }
      ],
      urls: [
        /\/waku\//,
        /\.waku\//
      ],
      headers: [],
      scripts: [
        /__WAKU_/,
        /waku/,
        /createRoot.*waku/
      ],
      requestHeaders: [
        { name: 'RSC', pattern: /1/ },
        { name: 'Content-Type', pattern: /text\/x-component/ }
      ]
    },
    versionPatterns: [
      { source: 'script', pattern: /waku@([\d.]+)/ },
      { source: 'script', pattern: /"waku":\s*"[~^]?([\d.]+)"/ }
    ],
    ssrIndicators: [
      { type: 'script', pattern: /__WAKU_SSR/ },
      { type: 'request', pattern: /\?_rsc=/ }
    ]
  },

  [FRAMEWORKS.REACT_ROUTER]: {
    name: 'React Router',
    priority: 10,
    signatures: {
      html: [
        { type: 'script', pattern: /__reactRouterVersion/ },
        { type: 'script', pattern: /react-router/ }
      ],
      urls: [
        /\/build\//,
        /\/_routes\//
      ],
      headers: [
        { name: 'x-powered-by', pattern: /React Router/i }
      ],
      scripts: [
        /__reactRouterVersion/,
        /react-router/,
        /createBrowserRouter/,
        /RouterProvider/,
        /@react-router/
      ],
      requestHeaders: [
        { name: 'RSC', pattern: /1/ },
        { name: 'Content-Type', pattern: /text\/x-component/ }
      ]
    },
    versionPatterns: [
      { source: 'script', pattern: /react-router@([\d.]+)/ },
      { source: 'script', pattern: /@react-router\/.*@([\d.]+)/ },
      { source: 'script', pattern: /"react-router":\s*"[~^]?([\d.]+)"/ }
    ],
    ssrIndicators: [
      { type: 'script', pattern: /__reactRouterVersion/ },
      { type: 'request', pattern: /\?_rsc=/ },
      { type: 'script', pattern: /createStaticHandler/ }
    ]
  },

  [FRAMEWORKS.REDWOOD]: {
    name: 'RedwoodJS',
    priority: 11,
    signatures: {
      html: [
        { type: 'script', pattern: /__REDWOOD__/ },
        { type: 'script', pattern: /redwoodjs/ }
      ],
      urls: [
        /\/\.redwood\//,
        /\/api\//
      ],
      headers: [],
      scripts: [
        /__REDWOOD__/,
        /@redwoodjs/,
        /RedwoodProvider/,
        /RedwoodApp/
      ],
      requestHeaders: [
        { name: 'RSC', pattern: /1/ },
        { name: 'Content-Type', pattern: /text\/x-component/ }
      ]
    },
    versionPatterns: [
      { source: 'script', pattern: /@redwoodjs\/.*@([\d.]+)/ },
      { source: 'script', pattern: /"@redwoodjs\/core":\s*"[~^]?([\d.]+)"/ }
    ],
    ssrIndicators: [
      { type: 'script', pattern: /__REDWOOD_SSR/ },
      { type: 'request', pattern: /\?_rsc=/ }
    ]
  }
};

/**
 * React Server Components / Flight Protocol signatures
 * Used for React2Shell detection
 */
export const RSC_SIGNATURES = {
  // Request indicators
  request: {
    headers: [
      { name: 'RSC', value: '1' },
      { name: 'Next-Router-State-Tree', pattern: /.+/ },
      { name: 'Next-Router-Prefetch', pattern: /.+/ },
      { name: 'Content-Type', pattern: /text\/x-component/ }
    ],
    queryParams: [
      '_rsc'
    ]
  },
  // Response indicators
  response: {
    contentTypes: [
      'text/x-component',
      'application/octet-stream'  // Flight binary format
    ],
    patterns: [
      /^\d+:/,           // Flight chunk format: "0:..."
      /\$@/,             // Chunk reference prefix
      /\$L/,             // Lazy component reference
      /\$S/,             // Symbol reference
      /\$F/,             // Server reference
      /\$undefined/      // Undefined value marker
    ]
  },
  // Dangerous Flight patterns (potential gadgets)
  gadgetIndicators: [
    /then\s*:/,          // Promise-like object
    /constructor/,       // Constructor access
    /_formData/,         // Form data reference
    /\$B/                // Blob handler
  ]
};

/**
 * Vuetify-specific signatures (for prototype pollution)
 */
export const VUETIFY_SIGNATURES = {
  scripts: [
    /vuetify/,
    /v-app/,
    /v-main/,
    /v-container/
  ],
  versionPatterns: [
    { source: 'script', pattern: /vuetify@([\d.]+)/ },
    { source: 'script', pattern: /Vuetify\.version\s*=\s*["']([\d.]+)["']/ }
  ]
};

/**
 * Get framework signatures sorted by priority
 * @returns {Array} - Array of [frameworkId, signatures] pairs
 */
export function getOrderedSignatures() {
  return Object.entries(FRAMEWORK_SIGNATURES)
    .sort((a, b) => a[1].priority - b[1].priority);
}

/**
 * Check if a string matches any pattern in an array
 * @param {string} str - String to check
 * @param {RegExp[]} patterns - Patterns to match against
 * @returns {boolean}
 */
export function matchesAnyPattern(str, patterns) {
  return patterns.some(pattern => pattern.test(str));
}

export default {
  FRAMEWORK_SIGNATURES,
  RSC_SIGNATURES,
  VUETIFY_SIGNATURES,
  getOrderedSignatures,
  matchesAnyPattern
};
