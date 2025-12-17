/**
 * BlueDragon Web Security - DOM Analyzer
 * Injected into main world to analyze DOM for vulnerabilities
 */

(function() {
  'use strict';

  /**
   * Report finding to content script
   */
  function reportFinding(type, data) {
    window.postMessage({
      type: 'DRAGON_DOM_FINDING',
      data: {
        findingType: type,
        ...data,
        timestamp: Date.now(),
        pageUrl: window.location.href
      }
    }, '*');
  }

  /**
   * Check for DOM XSS sinks
   */
  function checkDOMXSSSinks() {
    // Hook dangerous sinks
    const dangerousSinks = [
      { obj: Element.prototype, prop: 'innerHTML', name: 'innerHTML' },
      { obj: Element.prototype, prop: 'outerHTML', name: 'outerHTML' },
      { obj: Document.prototype, prop: 'write', name: 'document.write' },
      { obj: Document.prototype, prop: 'writeln', name: 'document.writeln' }
    ];

    for (const sink of dangerousSinks) {
      const original = Object.getOwnPropertyDescriptor(sink.obj, sink.prop);

      if (original && original.set) {
        Object.defineProperty(sink.obj, sink.prop, {
          ...original,
          set: function(value) {
            // Check if value contains user-controlled data
            if (typeof value === 'string' && containsUserInput(value)) {
              reportFinding('dom-xss-sink', {
                sink: sink.name,
                element: this.tagName,
                valuePreview: value.substring(0, 200),
                hasScript: value.includes('<script') || value.includes('javascript:'),
                hasEvent: /on\w+\s*=/i.test(value)
              });
            }

            return original.set.call(this, value);
          }
        });
      }
    }
  }

  /**
   * Check if value might contain user input
   */
  function containsUserInput(value) {
    // Check if URL parameters appear in value
    const params = new URLSearchParams(window.location.search);
    for (const [key, val] of params) {
      if (val && value.includes(val)) {
        return true;
      }
    }

    // Check hash
    if (window.location.hash && value.includes(window.location.hash.slice(1))) {
      return true;
    }

    return false;
  }

  /**
   * Check for insecure forms
   */
  function checkInsecureForms() {
    const forms = document.querySelectorAll('form');

    for (const form of forms) {
      const action = form.getAttribute('action') || '';
      const method = (form.getAttribute('method') || 'GET').toUpperCase();

      // Check for HTTP form submission
      if (action.startsWith('http://') && window.location.protocol === 'https:') {
        reportFinding('insecure-form', {
          action: action,
          method: method,
          fields: getFormFields(form),
          issue: 'HTTP form on HTTPS page'
        });
      }

      // Check for password fields without HTTPS
      const hasPassword = form.querySelector('input[type="password"]');
      if (hasPassword && window.location.protocol !== 'https:') {
        reportFinding('insecure-password-form', {
          action: action,
          issue: 'Password form on non-HTTPS page'
        });
      }

      // Check for missing CSRF tokens on state-changing forms
      if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
        const hasCSRFToken = form.querySelector('[name*="csrf"], [name*="token"], [name*="_token"]');
        if (!hasCSRFToken) {
          reportFinding('missing-csrf-token', {
            action: action,
            method: method,
            fields: getFormFields(form)
          });
        }
      }

      // Check for autocomplete on sensitive fields
      const sensitiveFields = form.querySelectorAll(
        'input[type="password"], input[name*="card"], input[name*="cvv"], input[name*="ssn"]'
      );

      for (const field of sensitiveFields) {
        if (field.getAttribute('autocomplete') !== 'off') {
          reportFinding('autocomplete-sensitive', {
            fieldName: field.name || field.id,
            fieldType: field.type
          });
        }
      }
    }
  }

  /**
   * Get form field names
   */
  function getFormFields(form) {
    const fields = [];
    const inputs = form.querySelectorAll('input, select, textarea');

    for (const input of inputs) {
      if (input.name) {
        fields.push({
          name: input.name,
          type: input.type || 'text'
        });
      }
    }

    return fields;
  }

  /**
   * Check for open redirects
   */
  function checkOpenRedirects() {
    // Check links with URL parameters
    const links = document.querySelectorAll('a[href*="url="], a[href*="redirect="], a[href*="next="], a[href*="return="]');

    for (const link of links) {
      const href = link.getAttribute('href');

      // Check if redirect parameter contains external URL
      const urlMatch = href.match(/[?&](url|redirect|next|return|returnUrl|returnTo|goto|destination)=([^&]+)/i);

      if (urlMatch) {
        const redirectValue = decodeURIComponent(urlMatch[2]);

        if (redirectValue.startsWith('http') || redirectValue.startsWith('//')) {
          reportFinding('potential-open-redirect', {
            href: href,
            parameter: urlMatch[1],
            redirectValue: redirectValue.substring(0, 200)
          });
        }
      }
    }

    // Check meta refresh
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      const content = metaRefresh.getAttribute('content') || '';
      if (content.toLowerCase().includes('url=')) {
        reportFinding('meta-refresh-redirect', {
          content: content
        });
      }
    }
  }

  /**
   * Check for exposed sensitive data in DOM
   */
  function checkExposedData() {
    const sensitivePatterns = [
      { name: 'AWS Key', pattern: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA)[A-Z0-9]{16}/g },
      { name: 'API Key', pattern: /api[_-]?key['":\s]*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi },
      { name: 'Bearer Token', pattern: /bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi },
      { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/g }
    ];

    // Check visible text content
    const body = document.body?.innerText || '';

    for (const { name, pattern } of sensitivePatterns) {
      const matches = body.match(pattern);
      if (matches && matches.length > 0) {
        reportFinding('exposed-sensitive-data', {
          type: name,
          count: matches.length,
          inDOM: true
        });
      }
    }

    // Check data attributes
    const dataElements = document.querySelectorAll('[data-api-key], [data-token], [data-secret]');
    if (dataElements.length > 0) {
      reportFinding('data-attribute-secrets', {
        count: dataElements.length,
        attributes: Array.from(dataElements).map(el =>
          Array.from(el.attributes)
            .filter(a => a.name.startsWith('data-'))
            .map(a => a.name)
        ).flat()
      });
    }
  }

  /**
   * Check for clickjacking vulnerabilities
   */
  function checkClickjacking() {
    // Check if page is in an iframe
    if (window.self !== window.top) {
      reportFinding('page-in-iframe', {
        parentOrigin: 'unknown' // Can't access cross-origin parent
      });
    }

    // Check for framebusting code
    const scripts = document.querySelectorAll('script');
    let hasFramebuster = false;

    for (const script of scripts) {
      const content = script.textContent || '';
      if (content.includes('top.location') || content.includes('self !== top')) {
        hasFramebuster = true;
        break;
      }
    }

    if (!hasFramebuster) {
      reportFinding('no-framebusting', {
        note: 'No JavaScript framebusting code detected. Check X-Frame-Options header.'
      });
    }
  }

  /**
   * Check for postMessage vulnerabilities
   */
  function checkPostMessage() {
    // Hook addEventListener for message events
    const originalAddEventListener = EventTarget.prototype.addEventListener;

    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (type === 'message' && this === window) {
        // Wrap the listener to check for origin validation
        const wrappedListener = function(event) {
          // Check if listener validates origin
          const listenerStr = listener.toString();
          const validatesOrigin =
            listenerStr.includes('origin') ||
            listenerStr.includes('source');

          if (!validatesOrigin) {
            reportFinding('postmessage-no-origin-check', {
              note: 'postMessage handler may not validate origin'
            });
          }

          return listener.call(this, event);
        };

        return originalAddEventListener.call(this, type, wrappedListener, options);
      }

      return originalAddEventListener.call(this, type, listener, options);
    };
  }

  /**
   * Initialize analyzer
   */
  function init() {
    // Run checks after page load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', runChecks);
    } else {
      runChecks();
    }

    // Also run after delay for dynamic content
    setTimeout(runChecks, 3000);
  }

  function runChecks() {
    checkDOMXSSSinks();
    checkInsecureForms();
    checkOpenRedirects();
    checkExposedData();
    checkClickjacking();
    checkPostMessage();
  }

  init();

  console.log('[BlueDragon] DOM analyzer installed');
})();
