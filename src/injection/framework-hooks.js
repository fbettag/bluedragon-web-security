/**
 * BlueDragon Web Security - Framework Hooks
 * Injected into main world to hook into framework internals
 */

(function() {
  'use strict';

  /**
   * Send discovery to content script
   */
  function reportDiscovery(type, data) {
    window.postMessage({
      type: 'DRAGON_FRAMEWORK_DISCOVERY',
      data: {
        discoveryType: type,
        ...data,
        timestamp: Date.now(),
        pageUrl: window.location.href
      }
    }, '*');
  }

  /**
   * Hook into React DevTools
   */
  function hookReact() {
    // Check for React DevTools hook
    const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;

    if (hook) {
      reportDiscovery('react', {
        hasDevTools: true,
        renderers: Object.keys(hook._renderers || {}).length
      });

      // Hook into component mount
      const originalOnCommitFiberRoot = hook.onCommitFiberRoot;
      if (originalOnCommitFiberRoot) {
        hook.onCommitFiberRoot = function(rendererID, root, priorityLevel) {
          // Analyze fiber tree for sensitive data
          try {
            analyzeReactFiber(root.current);
          } catch (e) {
            // Ignore errors in fiber analysis
          }

          return originalOnCommitFiberRoot.apply(this, arguments);
        };
      }
    }

    // Check for React version
    if (window.React?.version) {
      reportDiscovery('react-version', {
        version: window.React.version
      });
    }
  }

  /**
   * Analyze React Fiber tree for sensitive data
   */
  function analyzeReactFiber(fiber, depth = 0) {
    if (!fiber || depth > 10) return;

    // Check memoizedProps for API keys or tokens
    const props = fiber.memoizedProps;
    if (props && typeof props === 'object') {
      const sensitiveKeys = ['apiKey', 'api_key', 'token', 'secret', 'password', 'credential'];

      for (const key of sensitiveKeys) {
        if (props[key] && typeof props[key] === 'string' && props[key].length > 10) {
          reportDiscovery('react-prop-leak', {
            propName: key,
            componentName: fiber.type?.name || fiber.type?.displayName || 'Unknown',
            // Don't leak the actual value
            valueLength: props[key].length
          });
        }
      }
    }

    // Recurse into children
    if (fiber.child) {
      analyzeReactFiber(fiber.child, depth + 1);
    }
    if (fiber.sibling) {
      analyzeReactFiber(fiber.sibling, depth);
    }
  }

  /**
   * Hook into Vue
   */
  function hookVue() {
    // Vue 3
    if (window.__VUE__) {
      reportDiscovery('vue', {
        version: 3,
        devtools: !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__
      });
    }

    // Vue 2
    if (window.Vue?.version) {
      reportDiscovery('vue', {
        version: window.Vue.version,
        devtools: !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__
      });
    }

    // Check for Vuex store
    if (window.__VUEX__) {
      reportDiscovery('vuex-store', {
        present: true
      });
    }

    // Check for Pinia
    if (window.__pinia) {
      reportDiscovery('pinia-store', {
        present: true
      });
    }
  }

  /**
   * Hook into Angular
   */
  function hookAngular() {
    // Check for ng global
    if (window.ng) {
      reportDiscovery('angular', {
        hasNgGlobal: true
      });

      // Try to get version
      const versionEl = document.querySelector('[ng-version]');
      if (versionEl) {
        reportDiscovery('angular-version', {
          version: versionEl.getAttribute('ng-version')
        });
      }
    }

    // Check for Angular probe
    if (window.getAllAngularRootElements) {
      const roots = window.getAllAngularRootElements();
      reportDiscovery('angular-roots', {
        count: roots.length
      });
    }
  }

  /**
   * Hook into Nuxt/Svelte
   */
  function hookOtherFrameworks() {
    // Nuxt
    if (window.__NUXT__) {
      reportDiscovery('nuxt', {
        hasNuxtGlobal: true,
        ssrMode: window.__NUXT__.serverRendered || false,
        config: Object.keys(window.__NUXT__.config || {})
      });

      // Check for exposed runtime config
      if (window.__NUXT__.config?.public) {
        const publicConfig = window.__NUXT__.config.public;
        const sensitiveKeys = Object.keys(publicConfig).filter(k =>
          k.toLowerCase().includes('key') ||
          k.toLowerCase().includes('secret') ||
          k.toLowerCase().includes('token')
        );

        if (sensitiveKeys.length > 0) {
          reportDiscovery('nuxt-config-leak', {
            exposedKeys: sensitiveKeys
          });
        }
      }
    }

    // SvelteKit
    if (window.__sveltekit) {
      reportDiscovery('sveltekit', {
        hasSvelteKitGlobal: true
      });
    }

    // Next.js
    if (window.__NEXT_DATA__) {
      reportDiscovery('nextjs', {
        hasNextData: true,
        buildId: window.__NEXT_DATA__.buildId,
        page: window.__NEXT_DATA__.page,
        rsc: window.__NEXT_DATA__.rsc || false
      });

      // Check for exposed environment variables
      const props = window.__NEXT_DATA__.props?.pageProps;
      if (props) {
        const envKeys = Object.keys(props).filter(k =>
          k.toUpperCase().includes('KEY') ||
          k.toUpperCase().includes('SECRET') ||
          k.toUpperCase().includes('TOKEN')
        );

        if (envKeys.length > 0) {
          reportDiscovery('nextjs-prop-leak', {
            exposedKeys: envKeys
          });
        }
      }
    }
  }

  /**
   * Hook into error handling
   */
  function hookErrorHandling() {
    const originalOnError = window.onerror;

    window.onerror = function(message, source, lineno, colno, error) {
      // Check for framework-specific error patterns
      const errorStr = String(message) + String(error?.stack || '');

      if (errorStr.includes('chunk') || errorStr.includes('module')) {
        reportDiscovery('js-error', {
          type: 'chunk-error',
          message: String(message).substring(0, 200)
        });
      }

      if (errorStr.includes('React') || errorStr.includes('Hydration')) {
        reportDiscovery('react-error', {
          type: 'hydration',
          message: String(message).substring(0, 200)
        });
      }

      if (originalOnError) {
        return originalOnError.apply(this, arguments);
      }
    };
  }

  /**
   * Initialize hooks
   */
  function init() {
    // Wait for page to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', runHooks);
    } else {
      runHooks();
    }

    // Also run after a delay to catch late-loaded frameworks
    setTimeout(runHooks, 2000);
    setTimeout(runHooks, 5000);
  }

  function runHooks() {
    hookReact();
    hookVue();
    hookAngular();
    hookOtherFrameworks();
    hookErrorHandling();
  }

  init();

  console.log('[BlueDragon] Framework hooks installed');
})();
