/**
 * BlueDragon Web Security - Background Service Worker
 * Main background script handling state, messaging, and coordination
 */

import {
  MESSAGE_TYPES,
  DEFAULT_SETTINGS,
  SEVERITY,
  CVE_DATABASE
} from '../shared/constants.js';
import { RateLimiter, RequestLogger } from '../shared/safety-filters.js';

// Global state
let settings = { ...DEFAULT_SETTINGS };
let scanHistory = [];
let activeScans = new Map(); // tabId -> scanState
let frameworkCache = new Map(); // tabId -> framework info
let requestLogger = new RequestLogger(1000);
let collaboratorResults = [];

// Rate limiter for probes
const globalRateLimiter = new RateLimiter(5);

// Header rule ID for exploit testing
const HEADER_RULE_ID = 1;

/**
 * Initialize background worker
 */
async function init() {
  console.log('[BlueDragon] Background worker initializing...');

  // Load settings and history
  await loadSettings();
  await loadHistory();

  // Set up message listeners
  chrome.runtime.onMessage.addListener(handleMessage);

  // Set up tab listeners
  chrome.tabs.onUpdated.addListener(handleTabUpdated);
  chrome.tabs.onRemoved.addListener(handleTabRemoved);

  // Set up web request listeners for header analysis
  setupWebRequestListeners();

  // Set up alarm for periodic tasks
  chrome.alarms.create('collaboratorCheck', { periodInMinutes: 1 });
  chrome.alarms.onAlarm.addListener(handleAlarm);

  console.log('[BlueDragon] Background worker initialized');
}

/**
 * Load settings from storage
 */
async function loadSettings() {
  try {
    const stored = await chrome.storage.local.get('settings');
    if (stored.settings) {
      settings = { ...DEFAULT_SETTINGS, ...stored.settings };
    }
  } catch (e) {
    console.warn('[BlueDragon] Failed to load settings:', e);
  }
}

/**
 * Save settings to storage
 */
async function saveSettings() {
  try {
    await chrome.storage.local.set({ settings });
  } catch (e) {
    console.warn('[BlueDragon] Failed to save settings:', e);
  }
}

/**
 * Load scan history from storage
 */
async function loadHistory() {
  try {
    const stored = await chrome.storage.local.get('scanHistory');
    if (stored.scanHistory) {
      scanHistory = stored.scanHistory;
    }
  } catch (e) {
    console.warn('[BlueDragon] Failed to load history:', e);
  }
}

/**
 * Save history to storage
 */
async function saveHistory() {
  try {
    // Trim history if too large
    if (scanHistory.length > settings.maxHistoryItems) {
      scanHistory = scanHistory.slice(-settings.maxHistoryItems);
    }
    await chrome.storage.local.set({ scanHistory });
  } catch (e) {
    console.warn('[BlueDragon] Failed to save history:', e);
  }
}

/**
 * Handle messages from content scripts and popup
 */
function handleMessage(message, sender, sendResponse) {
  const tabId = sender.tab?.id;

  console.log('[BlueDragon] Background received:', message.type);

  switch (message.type) {
    // From content script
    case MESSAGE_TYPES.FRAMEWORK_DETECTED:
      handleFrameworkDetected(tabId, message.data);
      sendResponse({ success: true });
      break;

    case MESSAGE_TYPES.SCAN_COMPLETE:
      handleScanComplete(tabId, message.data);
      sendResponse({ success: true });
      break;

    case MESSAGE_TYPES.VULN_FOUND:
      handleVulnFound(tabId, message.data);
      sendResponse({ success: true });
      break;

    // From popup
    case MESSAGE_TYPES.MANUAL_SCAN:
      startManualScan(message.tabId || tabId)
        .then(result => sendResponse({ success: true, result }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true; // Async response

    case MESSAGE_TYPES.DEEP_SCAN:
      startDeepScan(message.tabId || tabId)
        .then(result => sendResponse({ success: true, result }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    case MESSAGE_TYPES.GET_HISTORY:
      sendResponse({
        success: true,
        history: scanHistory,
        stats: getHistoryStats()
      });
      break;

    case MESSAGE_TYPES.CLEAR_HISTORY:
      scanHistory = [];
      saveHistory();
      sendResponse({ success: true });
      break;

    case MESSAGE_TYPES.EXPORT_REQUEST:
      const exported = exportResults(message.format, message.data);
      sendResponse({ success: true, exported });
      break;

    case 'GET_SETTINGS':
      sendResponse({ success: true, settings });
      break;

    case 'SAVE_SETTINGS':
      settings = { ...settings, ...message.settings };
      saveSettings();
      sendResponse({ success: true });
      break;

    case 'GET_TAB_STATUS':
      const status = getTabStatus(message.tabId);
      sendResponse({ success: true, status });
      break;

    case 'TEST_COLLABORATOR':
      testCollaborator(message.config)
        .then(result => sendResponse({ success: true, result }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    case 'TEST_DISCORD_WEBHOOK':
      testDiscordWebhook(message.url)
        .then(result => sendResponse({ success: true, result }))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    case MESSAGE_TYPES.ENABLE_HEADER_RULES:
      enableHeaderRules(message.domain)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    case MESSAGE_TYPES.DISABLE_HEADER_RULES:
      disableHeaderRules()
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    default:
      console.warn('[BlueDragon] Unknown message type:', message.type);
      sendResponse({ success: false, error: 'Unknown message type' });
  }

  return false;
}

/**
 * Handle framework detection from content script
 */
function handleFrameworkDetected(tabId, data) {
  frameworkCache.set(tabId, {
    ...data,
    timestamp: Date.now()
  });

  // Update icon based on framework
  updateIcon(tabId, data.framework);
}

/**
 * Handle scan completion
 */
async function handleScanComplete(tabId, data) {
  console.log('[BlueDragon] Scan complete:', data.results?.length, 'findings');

  // Add to history
  if (settings.saveHistory && data.results?.length > 0) {
    for (const result of data.results) {
      scanHistory.push({
        ...result,
        tabId,
        scanType: data.scanType,
        viewed: false
      });
    }
    await saveHistory();
  }

  // Get critical and high severity findings
  const critical = data.results?.filter(r => r.severity === SEVERITY.CRITICAL) || [];
  const high = data.results?.filter(r => r.severity === SEVERITY.HIGH) || [];
  const hasHighSeverity = critical.length > 0 || high.length > 0;

  // Always send browser notifications for high severity in auto mode
  // or if notifications are enabled
  const isAutoMode = settings.autoScanEnabled || settings.scanMode === 'active';

  if (hasHighSeverity && (isAutoMode || settings.notificationsEnabled)) {
    const hostname = new URL(data.url).hostname;

    // Update badge to show alert
    chrome.action.setBadgeBackgroundColor({
      tabId,
      color: critical.length > 0 ? '#dc2626' : '#f97316'
    });
    chrome.action.setBadgeText({
      tabId,
      text: String(critical.length + high.length)
    });

    // Send browser notification
    const title = critical.length > 0
      ? `CRITICAL: ${critical[0].name}`
      : `HIGH: ${high[0].name}`;

    const message = critical.length > 0
      ? `${critical.length} critical${high.length > 0 ? `, ${high.length} high` : ''} severity on ${hostname}`
      : `${high.length} high severity issue${high.length > 1 ? 's' : ''} on ${hostname}`;

    sendNotification(title, message, {
      requireInteraction: critical.length > 0, // Keep critical notifications visible
      priority: critical.length > 0 ? 2 : 1
    });
  }

  // Send Discord webhook
  if (settings.discordWebhookEnabled && settings.discordWebhookUrl && hasHighSeverity) {
    sendDiscordWebhook(data.url, [...critical, ...high]);
  }

  // Update scan state
  activeScans.delete(tabId);
}

/**
 * Handle individual vulnerability found
 */
function handleVulnFound(tabId, data) {
  console.log('[BlueDragon] Vulnerability found:', data.type);

  // Could be used for real-time updates during scanning
}

/**
 * Start manual scan on tab
 */
async function startManualScan(tabId) {
  if (!tabId) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = tab?.id;
  }

  if (!tabId) throw new Error('No active tab');

  activeScans.set(tabId, { type: 'manual', startTime: Date.now() });

  // Send scan request to content script
  const response = await chrome.tabs.sendMessage(tabId, {
    type: MESSAGE_TYPES.START_SCAN,
    scanType: 'manual'
  });

  return response;
}

/**
 * Start deep scan on tab
 */
async function startDeepScan(tabId) {
  if (!tabId) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = tab?.id;
  }

  if (!tabId) throw new Error('No active tab');

  activeScans.set(tabId, { type: 'deep', startTime: Date.now() });

  const response = await chrome.tabs.sendMessage(tabId, {
    type: MESSAGE_TYPES.START_SCAN,
    scanType: 'deep'
  });

  return response;
}

/**
 * Get status for a specific tab
 */
function getTabStatus(tabId) {
  const framework = frameworkCache.get(tabId);
  const activeScan = activeScans.get(tabId);
  const tabHistory = scanHistory.filter(h => h.tabId === tabId);

  return {
    framework,
    isScanning: !!activeScan,
    scanType: activeScan?.type,
    findings: tabHistory.length,
    lastScan: tabHistory[tabHistory.length - 1]?.timestamp
  };
}

/**
 * Get history statistics
 */
function getHistoryStats() {
  const stats = {
    total: scanHistory.length,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    byType: {},
    byFramework: {},
    unviewed: 0
  };

  for (const item of scanHistory) {
    // By severity
    const severity = item.severity?.toLowerCase() || 'info';
    if (stats.bySeverity[severity] !== undefined) {
      stats.bySeverity[severity]++;
    }

    // By type
    const type = item.type || 'Unknown';
    stats.byType[type] = (stats.byType[type] || 0) + 1;

    // By framework
    const framework = item.framework || 'Unknown';
    stats.byFramework[framework] = (stats.byFramework[framework] || 0) + 1;

    // Unviewed
    if (!item.viewed) stats.unviewed++;
  }

  return stats;
}

/**
 * Export results in various formats
 */
function exportResults(format, data) {
  const results = data || scanHistory;

  switch (format) {
    case 'json':
      return JSON.stringify(results, null, 2);

    case 'nuclei':
      return generateNucleiTemplates(results);

    case 'markdown':
      return generateMarkdownReport(results);

    default:
      return JSON.stringify(results, null, 2);
  }
}

/**
 * Generate Nuclei templates from findings
 */
function generateNucleiTemplates(results) {
  const templates = [];

  for (const result of results) {
    if (!result.cve) continue;

    const template = `id: bluedragon-${result.cve.toLowerCase()}

info:
  name: ${result.name}
  author: BlueDragon
  severity: ${result.severity?.toLowerCase() || 'info'}
  description: ${result.description}
  reference:
    - https://nvd.nist.gov/vuln/detail/${result.cve}
  tags: ${result.framework?.toLowerCase() || 'web'},${result.type?.toLowerCase() || 'misc'}

http:
  - method: GET
    path:
      - "{{BaseURL}}${result.endpoint || '/'}"
    matchers:
      - type: word
        words:
          - "${result.framework || 'framework'}"
`;

    templates.push(template);
  }

  return templates.join('\n---\n\n');
}

/**
 * Generate Markdown report
 */
function generateMarkdownReport(results) {
  const stats = getHistoryStats();
  const grouped = {};

  // Group by severity
  for (const result of results) {
    const severity = result.severity || 'INFO';
    if (!grouped[severity]) grouped[severity] = [];
    grouped[severity].push(result);
  }

  let report = `# BlueDragon Web Security Scan Report

Generated: ${new Date().toISOString()}

## Summary

| Severity | Count |
|----------|-------|
| Critical | ${stats.bySeverity.critical} |
| High | ${stats.bySeverity.high} |
| Medium | ${stats.bySeverity.medium} |
| Low | ${stats.bySeverity.low} |
| Info | ${stats.bySeverity.info} |

## Findings

`;

  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  for (const severity of severityOrder) {
    const items = grouped[severity];
    if (!items || items.length === 0) continue;

    report += `### ${severity}\n\n`;

    for (const item of items) {
      report += `#### ${item.name || item.type}

- **CVE**: ${item.cve || 'N/A'}
- **URL**: ${item.url}
- **Framework**: ${item.framework || 'Unknown'}
- **Description**: ${item.description || 'No description'}

`;
    }
  }

  return report;
}

/**
 * Handle tab update
 */
function handleTabUpdated(tabId, changeInfo, tab) {
  if (changeInfo.status === 'complete') {
    // Tab finished loading - framework will be detected by content script
  }

  if (changeInfo.url) {
    // URL changed - clear cached framework info
    frameworkCache.delete(tabId);
    resetIcon(tabId);
  }
}

/**
 * Handle tab removal
 */
function handleTabRemoved(tabId) {
  frameworkCache.delete(tabId);
  activeScans.delete(tabId);
}

/**
 * Update extension icon based on framework
 */
function updateIcon(tabId, framework) {
  // For now, just use default icon
  // Can be enhanced to show different icons per framework
  chrome.action.setIcon({
    tabId,
    path: {
      16: 'icons/icon16.png',
      48: 'icons/icon48.png',
      128: 'icons/icon128.png'
    }
  }).catch(() => {});
}

/**
 * Reset icon to default
 */
function resetIcon(tabId) {
  chrome.action.setIcon({
    tabId,
    path: {
      16: 'icons/icon16.png',
      48: 'icons/icon48.png',
      128: 'icons/icon128.png'
    }
  }).catch(() => {});
}

/**
 * Set up web request listeners for header analysis
 */
function setupWebRequestListeners() {
  // Listen for response headers
  chrome.webRequest.onHeadersReceived.addListener(
    analyzeResponseHeaders,
    { urls: ['<all_urls>'] },
    ['responseHeaders']
  );
}

/**
 * Analyze response headers for security issues
 */
function analyzeResponseHeaders(details) {
  const headers = {};
  for (const header of details.responseHeaders || []) {
    headers[header.name.toLowerCase()] = header.value;
  }

  // Check for interesting headers
  const rscHeader = headers['rsc'];
  const nextAction = headers['next-action'];
  const xPoweredBy = headers['x-powered-by'];

  if (rscHeader || nextAction) {
    // Store for later analysis
    console.log('[BlueDragon] RSC/Server Action response detected:', details.url);
  }

  return {}; // Don't modify anything
}

/**
 * Send browser notification
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 * @param {Object} options - Additional options
 */
function sendNotification(title, message, options = {}) {
  const notificationOptions = {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `BlueDragon: ${title}`,
    message,
    priority: options.priority || 2,
    requireInteraction: options.requireInteraction || false
  };

  chrome.notifications.create(notificationOptions, (notificationId) => {
    // Auto-dismiss non-critical notifications after 10 seconds
    if (!options.requireInteraction) {
      setTimeout(() => {
        chrome.notifications.clear(notificationId);
      }, 10000);
    }
  });
}

/**
 * Send Discord webhook
 */
async function sendDiscordWebhook(url, results) {
  if (!settings.discordWebhookUrl) return;

  const hostname = new URL(url).hostname;
  const embed = {
    title: `Vulnerabilities Found on ${hostname}`,
    color: 0xef4444, // Red
    fields: results.slice(0, 10).map(r => ({
      name: `${r.severity}: ${r.name}`,
      value: r.description?.substring(0, 100) || 'No description',
      inline: false
    })),
    footer: {
      text: 'BlueDragon Web Security'
    },
    timestamp: new Date().toISOString()
  };

  try {
    await fetch(settings.discordWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] })
    });
  } catch (e) {
    console.error('[BlueDragon] Discord webhook failed:', e);
  }
}

/**
 * Test Discord webhook
 */
async function testDiscordWebhook(url) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content: 'BlueDragon Web Security - Webhook Test',
      embeds: [{
        title: 'Test Notification',
        description: 'If you see this, your webhook is working correctly!',
        color: 0x22c55e, // Green
        footer: { text: 'BlueDragon' }
      }]
    })
  });

  if (!response.ok) {
    throw new Error(`Webhook test failed: ${response.status}`);
  }

  return { success: true };
}

/**
 * Test collaborator connection
 */
async function testCollaborator(config) {
  // Implementation depends on collaborator type
  switch (config.type) {
    case 'burp':
      // Test Burp Collaborator
      return { success: true, message: 'Burp Collaborator configured' };

    case 'interactsh':
      // Test Interactsh
      return { success: true, message: 'Interactsh configured' };

    case 'custom':
      // Test custom webhook
      const response = await fetch(config.url, { method: 'HEAD' });
      return { success: response.ok, message: 'Custom webhook reachable' };

    default:
      throw new Error('Unknown collaborator type');
  }
}

/**
 * Handle alarms
 */
function handleAlarm(alarm) {
  switch (alarm.name) {
    case 'collaboratorCheck':
      checkCollaboratorCallbacks();
      break;
  }
}

/**
 * Check for collaborator callbacks
 */
async function checkCollaboratorCallbacks() {
  // Implementation for checking OOB callbacks
  // This would poll Interactsh or custom webhook for results
}

/**
 * Enable header modification rules for exploit testing
 * Removes Origin header to bypass CORS restrictions
 * @param {string} domain - Domain to apply rules to
 */
async function enableHeaderRules(domain) {
  try {
    // Remove any existing rule first
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [HEADER_RULE_ID]
    });

    // Add rule scoped to specific domain
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id: HEADER_RULE_ID,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [
            { header: 'Origin', operation: 'remove' }
          ]
        },
        condition: {
          urlFilter: `*://${domain}/*`,
          resourceTypes: ['xmlhttprequest']
        }
      }]
    });

    console.log('[BlueDragon] Header rules enabled for:', domain);
    return { success: true };
  } catch (e) {
    console.error('[BlueDragon] Failed to enable header rules:', e);
    return { success: false, error: e.message };
  }
}

/**
 * Disable header modification rules
 */
async function disableHeaderRules() {
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [HEADER_RULE_ID]
    });

    console.log('[BlueDragon] Header rules disabled');
    return { success: true };
  } catch (e) {
    console.error('[BlueDragon] Failed to disable header rules:', e);
    return { success: false, error: e.message };
  }
}

// Clear header rules on startup and install
chrome.runtime.onStartup.addListener(() => {
  disableHeaderRules();
});

chrome.runtime.onInstalled.addListener(() => {
  disableHeaderRules();
});

// Initialize
init();

// Export for module usage
export {
  settings,
  scanHistory,
  getHistoryStats
};
