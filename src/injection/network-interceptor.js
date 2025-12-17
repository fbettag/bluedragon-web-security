/**
 * BlueDragon Web Security - Network Interceptor
 * Injected into main world to intercept network requests
 */

(function() {
  'use strict';

  const MESSAGE_TYPE = 'DRAGON_NETWORK_CAPTURE';

  // Store original functions
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  /**
   * Send captured request to content script
   */
  function captureRequest(data) {
    window.postMessage({
      type: MESSAGE_TYPE,
      data: {
        ...data,
        timestamp: Date.now(),
        pageUrl: window.location.href
      }
    }, '*');
  }

  /**
   * Extract headers from Headers object or plain object
   */
  function extractHeaders(headers) {
    const result = {};

    if (headers instanceof Headers) {
      headers.forEach((value, key) => {
        result[key.toLowerCase()] = value;
      });
    } else if (headers && typeof headers === 'object') {
      for (const [key, value] of Object.entries(headers)) {
        result[key.toLowerCase()] = value;
      }
    }

    return result;
  }

  /**
   * Intercept fetch() calls
   */
  window.fetch = async function(input, init = {}) {
    const url = typeof input === 'string' ? input : input.url;
    const method = init.method || (input.method) || 'GET';
    const headers = extractHeaders(init.headers || (input.headers));

    // Capture outgoing request
    captureRequest({
      type: 'fetch',
      url: url,
      method: method.toUpperCase(),
      headers: headers,
      body: init.body ? truncateBody(init.body) : null,
      direction: 'outgoing'
    });

    // Call original fetch
    const response = await originalFetch.call(this, input, init);

    // Capture response info
    const responseHeaders = extractHeaders(response.headers);

    captureRequest({
      type: 'fetch',
      url: url,
      method: method.toUpperCase(),
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      direction: 'incoming'
    });

    // Check for interesting response patterns
    analyzeResponse(url, responseHeaders, method);

    return response;
  };

  /**
   * Intercept XMLHttpRequest
   */
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    this._dragonMethod = method;
    this._dragonUrl = url;
    return originalXHROpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    const xhr = this;
    const method = this._dragonMethod;
    const url = this._dragonUrl;

    // Get request headers
    const headers = {};

    // Capture outgoing request
    captureRequest({
      type: 'xhr',
      url: url,
      method: method?.toUpperCase() || 'GET',
      body: body ? truncateBody(body) : null,
      direction: 'outgoing'
    });

    // Listen for response
    xhr.addEventListener('load', function() {
      const responseHeaders = parseXHRHeaders(xhr.getAllResponseHeaders());

      captureRequest({
        type: 'xhr',
        url: url,
        method: method?.toUpperCase() || 'GET',
        status: xhr.status,
        statusText: xhr.statusText,
        headers: responseHeaders,
        direction: 'incoming'
      });

      analyzeResponse(url, responseHeaders, method);
    });

    return originalXHRSend.apply(this, arguments);
  };

  /**
   * Parse XHR response headers string
   */
  function parseXHRHeaders(headerString) {
    const headers = {};
    if (!headerString) return headers;

    const lines = headerString.trim().split('\r\n');
    for (const line of lines) {
      const index = line.indexOf(':');
      if (index > 0) {
        const key = line.substring(0, index).trim().toLowerCase();
        const value = line.substring(index + 1).trim();
        headers[key] = value;
      }
    }

    return headers;
  }

  /**
   * Truncate request body for logging
   */
  function truncateBody(body) {
    if (!body) return null;

    let str;
    if (typeof body === 'string') {
      str = body;
    } else if (body instanceof FormData) {
      str = '[FormData]';
    } else if (body instanceof URLSearchParams) {
      str = body.toString();
    } else if (body instanceof Blob) {
      str = `[Blob: ${body.size} bytes]`;
    } else if (body instanceof ArrayBuffer) {
      str = `[ArrayBuffer: ${body.byteLength} bytes]`;
    } else {
      try {
        str = JSON.stringify(body);
      } catch (e) {
        str = '[Complex Body]';
      }
    }

    return str.length > 1000 ? str.substring(0, 1000) + '...' : str;
  }

  /**
   * Analyze response for interesting patterns
   */
  function analyzeResponse(url, headers, method) {
    // Check for RSC / Flight protocol
    const contentType = headers['content-type'] || '';

    if (contentType.includes('text/x-component')) {
      window.postMessage({
        type: 'DRAGON_RSC_DETECTED',
        data: {
          url: url,
          method: method,
          contentType: contentType
        }
      }, '*');
    }

    // Check for Server Action headers
    if (headers['next-action'] || headers['rsc'] === '1') {
      window.postMessage({
        type: 'DRAGON_SERVER_ACTION',
        data: {
          url: url,
          method: method,
          headers: headers
        }
      }, '*');
    }

    // Check for Angular SSR markers
    if (headers['x-angular-cache'] || headers['x-rendered-by']?.includes('angular')) {
      window.postMessage({
        type: 'DRAGON_ANGULAR_SSR',
        data: {
          url: url,
          headers: headers
        }
      }, '*');
    }

    // Check for sensitive headers
    const sensitiveHeaders = ['authorization', 'x-api-key', 'x-auth-token'];
    for (const header of sensitiveHeaders) {
      if (headers[header]) {
        window.postMessage({
          type: 'DRAGON_SENSITIVE_HEADER',
          data: {
            url: url,
            header: header,
            // Don't leak the actual value
            present: true
          }
        }, '*');
      }
    }
  }

  // Intercept WebSocket for potential credential leaks
  const OriginalWebSocket = window.WebSocket;

  window.WebSocket = function(url, protocols) {
    captureRequest({
      type: 'websocket',
      url: url,
      direction: 'outgoing'
    });

    return new OriginalWebSocket(url, protocols);
  };

  window.WebSocket.prototype = OriginalWebSocket.prototype;
  window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  window.WebSocket.OPEN = OriginalWebSocket.OPEN;
  window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
  window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;

  // Intercept navigator.sendBeacon
  const originalSendBeacon = navigator.sendBeacon?.bind(navigator);

  if (originalSendBeacon) {
    navigator.sendBeacon = function(url, data) {
      captureRequest({
        type: 'beacon',
        url: url,
        body: data ? truncateBody(data) : null,
        direction: 'outgoing'
      });

      return originalSendBeacon(url, data);
    };
  }

  console.log('[BlueDragon] Network interceptor installed');
})();
