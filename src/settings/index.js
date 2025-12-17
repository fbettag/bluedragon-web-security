/**
 * BlueDragon Web Security - Settings Page
 */

import { DEFAULT_SETTINGS, MESSAGE_TYPES } from '../shared/constants.js';

let settings = { ...DEFAULT_SETTINGS };
let hasChanges = false;

/**
 * Initialize settings page
 */
async function init() {
  // Load current settings
  await loadSettings();

  // Populate form
  populateForm();

  // Set up event listeners
  setupEventListeners();

  // Update visibility based on current settings
  updateVisibility();
}

/**
 * Load settings from background
 */
async function loadSettings() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (response.success) {
      settings = { ...DEFAULT_SETTINGS, ...response.settings };
    }
  } catch (e) {
    console.warn('Failed to load settings:', e);
  }
}

/**
 * Populate form with current settings
 */
function populateForm() {
  // Scanning
  document.getElementById('autoScan').checked = settings.autoScanEnabled;
  document.getElementById('scanDelay').value = settings.scanDelay;
  document.getElementById('scanMode').value = settings.scanMode;
  document.getElementById('maxRequests').value = settings.maxRequestsPerSecond;

  // Safety
  document.getElementById('skipPayment').checked = settings.skipPaymentEndpoints;
  document.getElementById('requireConfirm').checked = settings.requireConfirmation;
  document.getElementById('blocklist').value = settings.customBlocklist || '';

  // Collaborator
  document.getElementById('collaboratorType').value = settings.collaboratorType;
  document.getElementById('interactshServer').value = settings.interactshServer || 'oast.fun';
  document.getElementById('burpCollaborator').value = settings.burpCollaboratorUrl || '';
  document.getElementById('customWebhook').value = settings.customWebhookUrl || '';

  // Proxy
  document.getElementById('proxyEnabled').checked = settings.proxyEnabled;
  document.getElementById('proxyHost').value = settings.proxyHost;
  document.getElementById('proxyPort').value = settings.proxyPort;

  // Notifications
  document.getElementById('notifications').checked = settings.notificationsEnabled;
  document.getElementById('discordEnabled').checked = settings.discordWebhookEnabled;
  document.getElementById('discordWebhook').value = settings.discordWebhookUrl || '';

  // History
  document.getElementById('saveHistory').checked = settings.saveHistory;
  document.getElementById('maxHistory').value = settings.maxHistoryItems;

  // Export
  document.getElementById('defaultExport').value = settings.defaultExportFormat;
  document.getElementById('includePoC').checked = settings.includePoC;
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
  // Track changes
  document.querySelectorAll('input, select, textarea').forEach(el => {
    el.addEventListener('change', () => {
      hasChanges = true;
    });
    el.addEventListener('input', () => {
      hasChanges = true;
    });
  });

  // Visibility toggles
  document.getElementById('collaboratorType').addEventListener('change', updateVisibility);
  document.getElementById('proxyEnabled').addEventListener('change', updateVisibility);
  document.getElementById('discordEnabled').addEventListener('change', updateVisibility);

  // Test buttons
  document.getElementById('testInteractsh').addEventListener('click', testInteractsh);
  document.getElementById('testBurp').addEventListener('click', testBurp);
  document.getElementById('testCustom').addEventListener('click', testCustomWebhook);
  document.getElementById('testDiscord').addEventListener('click', testDiscord);

  // Clear history
  document.getElementById('clearHistory').addEventListener('click', clearHistory);

  // Save/Reset
  document.getElementById('saveBtn').addEventListener('click', saveSettings);
  document.getElementById('resetBtn').addEventListener('click', resetSettings);

  // Warn on unsaved changes
  window.addEventListener('beforeunload', (e) => {
    if (hasChanges) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
}

/**
 * Update visibility of conditional sections
 */
function updateVisibility() {
  const collaboratorType = document.getElementById('collaboratorType').value;
  const proxyEnabled = document.getElementById('proxyEnabled').checked;
  const discordEnabled = document.getElementById('discordEnabled').checked;

  // Collaborator configs
  document.querySelectorAll('.collaborator-config').forEach(el => {
    el.style.display = el.dataset.type === collaboratorType ? 'flex' : 'none';
  });

  // Proxy configs
  document.querySelectorAll('.proxy-config').forEach(el => {
    el.style.display = proxyEnabled ? 'flex' : 'none';
  });

  // Discord config
  document.querySelectorAll('.discord-config').forEach(el => {
    el.style.display = discordEnabled ? 'flex' : 'none';
  });
}

/**
 * Gather settings from form
 */
function gatherSettings() {
  return {
    // Scanning
    autoScanEnabled: document.getElementById('autoScan').checked,
    scanDelay: parseInt(document.getElementById('scanDelay').value, 10),
    scanMode: document.getElementById('scanMode').value,
    maxRequestsPerSecond: parseInt(document.getElementById('maxRequests').value, 10),

    // Safety
    skipPaymentEndpoints: document.getElementById('skipPayment').checked,
    requireConfirmation: document.getElementById('requireConfirm').checked,
    customBlocklist: document.getElementById('blocklist').value,

    // Collaborator
    collaboratorType: document.getElementById('collaboratorType').value,
    interactshServer: document.getElementById('interactshServer').value,
    burpCollaboratorUrl: document.getElementById('burpCollaborator').value,
    customWebhookUrl: document.getElementById('customWebhook').value,

    // Proxy
    proxyEnabled: document.getElementById('proxyEnabled').checked,
    proxyHost: document.getElementById('proxyHost').value,
    proxyPort: parseInt(document.getElementById('proxyPort').value, 10),

    // Notifications
    notificationsEnabled: document.getElementById('notifications').checked,
    discordWebhookEnabled: document.getElementById('discordEnabled').checked,
    discordWebhookUrl: document.getElementById('discordWebhook').value,

    // History
    saveHistory: document.getElementById('saveHistory').checked,
    maxHistoryItems: parseInt(document.getElementById('maxHistory').value, 10),

    // Export
    defaultExportFormat: document.getElementById('defaultExport').value,
    includePoC: document.getElementById('includePoC').checked
  };
}

/**
 * Save settings
 */
async function saveSettings() {
  const newSettings = gatherSettings();

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'SAVE_SETTINGS',
      settings: newSettings
    });

    if (response.success) {
      settings = newSettings;
      hasChanges = false;
      showToast('Settings saved', 'success');
    } else {
      showToast('Failed to save settings', 'error');
    }
  } catch (e) {
    showToast('Error saving settings', 'error');
  }
}

/**
 * Reset to defaults
 */
function resetSettings() {
  if (confirm('Reset all settings to defaults?')) {
    settings = { ...DEFAULT_SETTINGS };
    populateForm();
    hasChanges = true;
    showToast('Settings reset to defaults', 'success');
  }
}

/**
 * Test Interactsh connection
 */
async function testInteractsh() {
  const server = document.getElementById('interactshServer').value;
  const resultEl = document.getElementById('interactshResult');

  resultEl.classList.remove('hidden', 'success', 'error');
  resultEl.textContent = 'Testing...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'TEST_COLLABORATOR',
      config: { type: 'interactsh', server }
    });

    if (response.success) {
      resultEl.classList.add('success');
      resultEl.textContent = 'Interactsh configured successfully';
    } else {
      resultEl.classList.add('error');
      resultEl.textContent = response.error || 'Test failed';
    }
  } catch (e) {
    resultEl.classList.add('error');
    resultEl.textContent = e.message;
  }
}

/**
 * Test Burp Collaborator
 */
async function testBurp() {
  const url = document.getElementById('burpCollaborator').value;
  const resultEl = document.getElementById('burpResult');

  if (!url) {
    resultEl.classList.remove('hidden');
    resultEl.classList.add('error');
    resultEl.textContent = 'Please enter a Collaborator URL';
    return;
  }

  resultEl.classList.remove('hidden', 'success', 'error');
  resultEl.textContent = 'Testing...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'TEST_COLLABORATOR',
      config: { type: 'burp', url }
    });

    if (response.success) {
      resultEl.classList.add('success');
      resultEl.textContent = 'Burp Collaborator configured';
    } else {
      resultEl.classList.add('error');
      resultEl.textContent = response.error || 'Test failed';
    }
  } catch (e) {
    resultEl.classList.add('error');
    resultEl.textContent = e.message;
  }
}

/**
 * Test custom webhook
 */
async function testCustomWebhook() {
  const url = document.getElementById('customWebhook').value;
  const resultEl = document.getElementById('customResult');

  if (!url) {
    resultEl.classList.remove('hidden');
    resultEl.classList.add('error');
    resultEl.textContent = 'Please enter a webhook URL';
    return;
  }

  resultEl.classList.remove('hidden', 'success', 'error');
  resultEl.textContent = 'Testing...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'TEST_COLLABORATOR',
      config: { type: 'custom', url }
    });

    if (response.success) {
      resultEl.classList.add('success');
      resultEl.textContent = 'Webhook is reachable';
    } else {
      resultEl.classList.add('error');
      resultEl.textContent = response.error || 'Test failed';
    }
  } catch (e) {
    resultEl.classList.add('error');
    resultEl.textContent = e.message;
  }
}

/**
 * Test Discord webhook
 */
async function testDiscord() {
  const url = document.getElementById('discordWebhook').value;
  const resultEl = document.getElementById('discordResult');

  if (!url) {
    resultEl.classList.remove('hidden');
    resultEl.classList.add('error');
    resultEl.textContent = 'Please enter a Discord webhook URL';
    return;
  }

  resultEl.classList.remove('hidden', 'success', 'error');
  resultEl.textContent = 'Sending test message...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'TEST_DISCORD_WEBHOOK',
      url
    });

    if (response.success) {
      resultEl.classList.add('success');
      resultEl.textContent = 'Test message sent! Check your Discord channel.';
    } else {
      resultEl.classList.add('error');
      resultEl.textContent = response.error || 'Test failed';
    }
  } catch (e) {
    resultEl.classList.add('error');
    resultEl.textContent = e.message;
  }
}

/**
 * Clear history
 */
async function clearHistory() {
  if (!confirm('Delete all scan history? This cannot be undone.')) {
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.CLEAR_HISTORY
    });

    if (response.success) {
      showToast('History cleared', 'success');
    } else {
      showToast('Failed to clear history', 'error');
    }
  } catch (e) {
    showToast('Error clearing history', 'error');
  }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 100px;
    left: 50%;
    transform: translateX(-50%);
    padding: 12px 24px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
    z-index: 1000;
  `;

  if (type === 'success') {
    toast.style.borderColor = 'var(--severity-low)';
  } else if (type === 'error') {
    toast.style.borderColor = 'var(--severity-critical)';
  }

  document.body.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', init);
