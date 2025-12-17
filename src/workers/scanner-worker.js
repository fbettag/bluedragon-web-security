/**
 * BlueDragon Web Security - Scanner Worker
 * Offloads scanning operations to a background thread
 */

/**
 * Process scanner task
 */
async function processTask(task) {
  const { type, data } = task;

  switch (type) {
    case 'analyzeResponse':
      return analyzeResponse(data);
    case 'checkPatterns':
      return checkPatterns(data);
    case 'parseFlightProtocol':
      return parseFlightProtocol(data);
    default:
      throw new Error(`Unknown task type: ${type}`);
  }
}

/**
 * Analyze response for vulnerability indicators
 */
function analyzeResponse(data) {
  const { body, headers, url } = data;
  const findings = [];

  // Check for sensitive data exposure
  const sensitivePatterns = [
    { pattern: /password['"]\s*:\s*['"][^'"]+['"]/gi, type: 'password_exposure' },
    { pattern: /api[_-]?key['"]\s*:\s*['"][^'"]+['"]/gi, type: 'api_key_exposure' },
    { pattern: /secret['"]\s*:\s*['"][^'"]+['"]/gi, type: 'secret_exposure' },
    { pattern: /token['"]\s*:\s*['"][a-zA-Z0-9_-]{20,}['"]/gi, type: 'token_exposure' },
    { pattern: /private[_-]?key/gi, type: 'private_key_reference' }
  ];

  for (const { pattern, type } of sensitivePatterns) {
    if (pattern.test(body)) {
      findings.push({
        type,
        url,
        severity: 'HIGH'
      });
    }
  }

  // Check for stack traces
  const stackTracePatterns = [
    /at\s+[\w.]+\s+\([^)]+:\d+:\d+\)/,
    /Error:.*\n\s+at\s+/,
    /Traceback \(most recent call last\)/,
    /Exception in thread/
  ];

  for (const pattern of stackTracePatterns) {
    if (pattern.test(body)) {
      findings.push({
        type: 'stack_trace_exposure',
        url,
        severity: 'MEDIUM'
      });
      break;
    }
  }

  // Check for debug info
  if (body.includes('__NEXT_DATA__') && body.includes('"buildId"')) {
    const buildIdMatch = body.match(/"buildId"\s*:\s*"([^"]+)"/);
    if (buildIdMatch) {
      findings.push({
        type: 'build_info_exposure',
        url,
        buildId: buildIdMatch[1],
        severity: 'INFO'
      });
    }
  }

  return findings;
}

/**
 * Check content against vulnerability patterns
 */
function checkPatterns(data) {
  const { content, patterns } = data;
  const matches = [];

  for (const { name, regex, severity } of patterns) {
    const pattern = new RegExp(regex, 'gi');
    let match;

    while ((match = pattern.exec(content)) !== null) {
      matches.push({
        name,
        severity,
        match: match[0],
        index: match.index,
        context: content.substring(
          Math.max(0, match.index - 50),
          Math.min(content.length, match.index + match[0].length + 50)
        )
      });
    }
  }

  return matches;
}

/**
 * Parse React Flight Protocol response
 */
function parseFlightProtocol(data) {
  const { body } = data;
  const result = {
    isFlightResponse: false,
    chunks: [],
    serverActions: [],
    clientReferences: [],
    errors: []
  };

  // Check if this is a Flight response
  if (!body || typeof body !== 'string') {
    return result;
  }

  // Flight responses are newline-delimited JSON
  const lines = body.split('\n').filter(line => line.trim());

  if (lines.length === 0) {
    return result;
  }

  // Check for Flight format markers
  const flightMarkers = ['$', '@', 'I:', 'M:', 'S:', 'H:', 'E:'];
  let hasFlightMarker = false;

  for (const line of lines) {
    for (const marker of flightMarkers) {
      if (line.startsWith(marker) || line.includes(`"${marker}`)) {
        hasFlightMarker = true;
        break;
      }
    }
    if (hasFlightMarker) break;
  }

  if (!hasFlightMarker) {
    return result;
  }

  result.isFlightResponse = true;

  // Parse each chunk
  for (const line of lines) {
    try {
      // Try to parse as JSON
      const colonIndex = line.indexOf(':');
      if (colonIndex > -1 && colonIndex < 10) {
        const id = line.substring(0, colonIndex);
        const content = line.substring(colonIndex + 1);

        try {
          const parsed = JSON.parse(content);
          result.chunks.push({
            id,
            type: getChunkType(id, parsed),
            content: parsed
          });

          // Extract server action references
          if (parsed && typeof parsed === 'object') {
            extractServerActions(parsed, result.serverActions);
            extractClientReferences(parsed, result.clientReferences);
          }
        } catch {
          // Raw chunk
          result.chunks.push({
            id,
            type: 'raw',
            content
          });
        }
      }
    } catch (e) {
      result.errors.push({
        line: line.substring(0, 100),
        error: e.message
      });
    }
  }

  return result;
}

/**
 * Get chunk type from Flight protocol
 */
function getChunkType(id, content) {
  if (id.startsWith('$')) return 'promise';
  if (id.startsWith('@')) return 'reference';
  if (id === 'I' || id.startsWith('I:')) return 'import';
  if (id === 'M' || id.startsWith('M:')) return 'module';
  if (id === 'S' || id.startsWith('S:')) return 'symbol';
  if (id === 'H' || id.startsWith('H:')) return 'hint';
  if (id === 'E' || id.startsWith('E:')) return 'error';

  if (Array.isArray(content)) return 'array';
  if (typeof content === 'object' && content !== null) return 'object';

  return 'unknown';
}

/**
 * Extract server action references from Flight data
 */
function extractServerActions(obj, actions, path = '') {
  if (!obj || typeof obj !== 'object') return;

  // Check for server action markers
  if (obj.$$typeof === Symbol.for('react.server.reference') ||
      obj.$$id || obj.$$bound) {
    actions.push({
      path,
      id: obj.$$id,
      bound: obj.$$bound,
      name: obj.$$name || obj.name
    });
    return;
  }

  // Recurse into arrays and objects
  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      extractServerActions(item, actions, `${path}[${index}]`);
    });
  } else {
    for (const [key, value] of Object.entries(obj)) {
      extractServerActions(value, actions, path ? `${path}.${key}` : key);
    }
  }
}

/**
 * Extract client component references from Flight data
 */
function extractClientReferences(obj, references, path = '') {
  if (!obj || typeof obj !== 'object') return;

  // Check for client reference markers
  if (obj.$$typeof === Symbol.for('react.client.reference') ||
      obj.$$typeof === 'client.reference') {
    references.push({
      path,
      id: obj.$$id,
      chunks: obj.chunks,
      name: obj.$$name || obj.name
    });
    return;
  }

  // Recurse
  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      extractClientReferences(item, references, `${path}[${index}]`);
    });
  } else {
    for (const [key, value] of Object.entries(obj)) {
      extractClientReferences(value, references, path ? `${path}.${key}` : key);
    }
  }
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
