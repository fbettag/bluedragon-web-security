/**
 * BlueDragon Web Security - Version Fingerprinting
 * Extracts framework versions from static assets
 */

/**
 * Extract version information from static asset URLs and content
 * @param {Document} doc - Document to analyze
 * @returns {Promise<Object>} - Extracted version information
 */
export async function extractVersionFromAssets(doc) {
  const versions = {
    nextjs: null,
    react: null,
    angular: null,
    svelte: null,
    sveltekit: null,
    vue: null,
    nuxt: null,
    vuetify: null,
    buildId: null,
    buildTime: null
  };

  // Collect all script and link URLs
  const scripts = Array.from(doc.querySelectorAll('script[src]'));
  const links = Array.from(doc.querySelectorAll('link[href]'));

  // Analyze Next.js assets
  const nextVersion = analyzeNextJsAssets(scripts, links);
  if (nextVersion) {
    versions.nextjs = nextVersion.version;
    versions.react = nextVersion.reactVersion;
    versions.buildId = nextVersion.buildId;
  }

  // Analyze Angular assets
  const angularVersion = analyzeAngularAssets(scripts, doc);
  if (angularVersion) {
    versions.angular = angularVersion;
  }

  // Analyze SvelteKit assets
  const svelteVersion = analyzeSvelteKitAssets(scripts);
  if (svelteVersion) {
    versions.sveltekit = svelteVersion.kit;
    versions.svelte = svelteVersion.svelte;
  }

  // Analyze Vue/Nuxt assets
  const vueVersion = analyzeVueAssets(scripts);
  if (vueVersion) {
    versions.vue = vueVersion.vue;
    versions.nuxt = vueVersion.nuxt;
    versions.vuetify = vueVersion.vuetify;
  }

  return versions;
}

/**
 * Analyze Next.js static assets for version info
 * @param {HTMLScriptElement[]} scripts - Script elements
 * @param {HTMLLinkElement[]} links - Link elements
 * @returns {Object|null} - Version info
 */
function analyzeNextJsAssets(scripts, links) {
  let buildId = null;
  let version = null;
  let reactVersion = null;

  for (const script of scripts) {
    const src = script.src;

    // Extract build ID from path
    const buildMatch = src.match(/_next\/static\/([a-zA-Z0-9_-]+)\//);
    if (buildMatch) {
      buildId = buildMatch[1];
    }

    // Try to extract version from chunk filenames
    // Next.js sometimes includes version in framework chunk names
    const versionMatch = src.match(/framework-([a-f0-9]+)\.js/);
    if (versionMatch) {
      // This is a hash, not a version, but we can note it
    }
  }

  // Check for version in link preloads
  for (const link of links) {
    const href = link.href;
    if (href.includes('_next/static')) {
      const buildMatch = href.match(/_next\/static\/([a-zA-Z0-9_-]+)\//);
      if (buildMatch && !buildId) {
        buildId = buildMatch[1];
      }
    }
  }

  return buildId ? { buildId, version, reactVersion } : null;
}

/**
 * Analyze Angular assets for version info
 * @param {HTMLScriptElement[]} scripts - Script elements
 * @param {Document} doc - Document
 * @returns {string|null} - Angular version
 */
function analyzeAngularAssets(scripts, doc) {
  // First check ng-version attribute
  const ngVersion = doc.querySelector('[ng-version]');
  if (ngVersion) {
    return ngVersion.getAttribute('ng-version');
  }

  // Check script filenames for version patterns
  for (const script of scripts) {
    const src = script.src;

    // Angular CLI generates these patterns
    const patterns = [
      /angular[\/\\@]core[\/\\@]([\d.]+)/,
      /angular-core@([\d.]+)/
    ];

    for (const pattern of patterns) {
      const match = src.match(pattern);
      if (match) {
        return match[1];
      }
    }
  }

  return null;
}

/**
 * Analyze SvelteKit assets for version info
 * @param {HTMLScriptElement[]} scripts - Script elements
 * @returns {Object|null} - Version info
 */
function analyzeSvelteKitAssets(scripts) {
  let kitVersion = null;
  let svelteVersion = null;

  for (const script of scripts) {
    const src = script.src;

    // SvelteKit immutable asset patterns
    if (src.includes('/_app/immutable/')) {
      // Check for version in path
      const versionMatch = src.match(/@sveltejs[\/\\]kit@([\d.]+)/);
      if (versionMatch) {
        kitVersion = versionMatch[1];
      }

      const svelteMatch = src.match(/svelte@([\d.]+)/);
      if (svelteMatch) {
        svelteVersion = svelteMatch[1];
      }
    }
  }

  return (kitVersion || svelteVersion) ? { kit: kitVersion, svelte: svelteVersion } : null;
}

/**
 * Analyze Vue/Nuxt assets for version info
 * @param {HTMLScriptElement[]} scripts - Script elements
 * @returns {Object|null} - Version info
 */
function analyzeVueAssets(scripts) {
  let vueVersion = null;
  let nuxtVersion = null;
  let vuetifyVersion = null;

  for (const script of scripts) {
    const src = script.src;

    // Nuxt patterns
    if (src.includes('/_nuxt/')) {
      const nuxtMatch = src.match(/nuxt@([\d.]+)/);
      if (nuxtMatch) {
        nuxtVersion = nuxtMatch[1];
      }
    }

    // Vue patterns
    const vueMatch = src.match(/vue@([\d.]+)/);
    if (vueMatch) {
      vueVersion = vueMatch[1];
    }

    // Vuetify patterns
    const vuetifyMatch = src.match(/vuetify@([\d.]+)/);
    if (vuetifyMatch) {
      vuetifyVersion = vuetifyMatch[1];
    }
  }

  return (vueVersion || nuxtVersion || vuetifyVersion)
    ? { vue: vueVersion, nuxt: nuxtVersion, vuetify: vuetifyVersion }
    : null;
}

/**
 * Fetch and analyze a script for version information
 * This is more intrusive and should only be done when needed
 * @param {string} url - Script URL
 * @returns {Promise<Object|null>} - Extracted info
 */
export async function fetchAndAnalyzeScript(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) return null;

    const content = await response.text();

    const info = {
      versions: {},
      buildInfo: {}
    };

    // Look for version strings in the content
    const versionPatterns = [
      { name: 'react', pattern: /React\.version\s*=\s*["']([\d.]+)["']/ },
      { name: 'react', pattern: /"react":\s*"[~^]?([\d.]+)"/ },
      { name: 'next', pattern: /"next":\s*"[~^]?([\d.]+)"/ },
      { name: 'angular', pattern: /@angular\/core@([\d.]+)/ },
      { name: 'vue', pattern: /Vue\.version\s*=\s*["']([\d.]+)["']/ },
      { name: 'svelte', pattern: /svelte@([\d.]+)/ },
      { name: 'nuxt', pattern: /"nuxt":\s*"[~^]?([\d.]+)"/ },
      { name: 'vuetify', pattern: /Vuetify\.version\s*=\s*["']([\d.]+)["']/ }
    ];

    for (const { name, pattern } of versionPatterns) {
      const match = content.match(pattern);
      if (match) {
        info.versions[name] = match[1];
      }
    }

    // Look for build timestamp
    const buildTimeMatch = content.match(/buildTime['":\s]+([\d]+)/);
    if (buildTimeMatch) {
      info.buildInfo.timestamp = parseInt(buildTimeMatch[1], 10);
      info.buildInfo.date = new Date(info.buildInfo.timestamp).toISOString();
    }

    return Object.keys(info.versions).length > 0 ? info : null;
  } catch (e) {
    console.warn('[BlueDragon] Failed to fetch script:', url, e);
    return null;
  }
}

/**
 * Generate version fingerprint hash for caching
 * @param {Object} versions - Version object
 * @returns {string} - Fingerprint hash
 */
export function generateFingerprint(versions) {
  const data = JSON.stringify(versions);
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

export default {
  extractVersionFromAssets,
  fetchAndAnalyzeScript,
  generateFingerprint
};
