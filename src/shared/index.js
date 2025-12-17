/**
 * BlueDragon Web Security - Shared Module Index
 * Re-exports all shared utilities for convenience
 */

// Constants
export * from './constants.js';
export { default as constants } from './constants.js';

// Safety filters
export * from './safety-filters.js';
export { default as safetyFilters } from './safety-filters.js';

// Framework signatures
export * from './framework-signatures.js';
export { default as frameworkSignatures } from './framework-signatures.js';

// Utility functions
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

export function parseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

export function getHostname(url) {
  const parsed = parseUrl(url);
  return parsed ? parsed.hostname : null;
}

export function isInternalUrl(url) {
  const internal = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
  const hostname = getHostname(url);
  return internal.includes(hostname) ||
         hostname?.endsWith('.local') ||
         hostname?.endsWith('.internal') ||
         /^192\.168\./.test(hostname) ||
         /^10\./.test(hostname) ||
         /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname);
}

export function truncate(str, maxLength, suffix = '...') {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength - suffix.length) + suffix;
}

export function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

export function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleString();
}

export function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

/**
 * Deep merge objects (useful for settings)
 */
export function deepMerge(target, source) {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    if (source[key] instanceof Object && key in target && target[key] instanceof Object) {
      result[key] = deepMerge(target[key], source[key]);
    } else {
      result[key] = source[key];
    }
  }

  return result;
}

/**
 * Debounce function calls
 */
export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function calls
 */
export function throttle(func, limit) {
  let inThrottle;
  return function executedFunction(...args) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}
